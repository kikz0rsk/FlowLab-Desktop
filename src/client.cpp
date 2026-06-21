#include <boost/asio/completion_condition.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>

#include "client.h"

#include "connection_manager.h"
#include "dns_manager.h"
#include "file_writer.h"
#include "protocol.h"
#include "proxy_service.h"
#include "tcp_connection.h"
#include "udp_connection.h"


Client::Client(
	boost::asio::ip::tcp::socket clientSocket,
	pcpp::IPAddress clientIp,
	uint16_t port
) : clientSocket(std::move(clientSocket)), clientIp(clientIp), port(port) {}

Client::~Client() = default;

void Client::handleClient() {
	boost::asio::co_spawn(
		clientSocket.get_executor(),
		[ptr = shared_from_this()] -> boost::asio::awaitable<void> {
			return ptr->decryptIncomingCoroutine();
		},
		boost::asio::detached
	);
	boost::asio::co_spawn(
		clientSocket.get_executor(),
		[ptr = shared_from_this()] -> boost::asio::awaitable<void> {
			return ptr->encryptOutgoingCoroutine();
		},
		boost::asio::detached
	);
}

boost::asio::awaitable<void> Client::decryptIncomingCoroutine() {
	while (clientSocket.is_open()) {
		std::array<uint8_t, 16 * 1024> data{};
		auto len = co_await clientSocket.async_read_some(boost::asio::buffer(data, data.size()), boost::asio::use_awaitable);
		if (len == 0) {
			break;
		}
		this->tlsConnection->received_data(std::span<const uint8_t>(data.data(), len));

		if (!this->getUnencryptedQueueFromDevice().empty()) {
			processIncomingData();
		}
	}
}

bool Client::processIncomingData() {
	auto& buffer = getUnencryptedQueueFromDevice();
	if (buffer.size() < 20) {
		return false;
	}

	bool isIpv6 = false;
	int totalLength{};

	if (((buffer[0] >> 4) & 0xF) == 6) {
		isIpv6 = true;
	}

	if (isIpv6) {
		const auto payloadLength = (buffer[4] << 8) | (buffer[5]);
		totalLength = payloadLength + 40;
	} else {
		totalLength = (buffer[2] << 8) | (buffer[3]);
	}

	if (std::cmp_less(buffer.size(), totalLength)) {
		// we don't have the full packet yet
		return false;
	}

	std::vector packetBuffer(buffer.begin(), buffer.begin() + totalLength);
	buffer.erase(buffer.begin(), buffer.begin() + totalLength);

	timeval time{};
	gettimeofday(&time, nullptr);
	pcpp::RawPacket packet(packetBuffer.data(), totalLength, time, false, isIpv6 ? pcpp::LINKTYPE_IPV6 : pcpp::LINKTYPE_IPV4);
	pcpp::Packet parsedPacket(&packet);

	pcpp::IPAddress srcIp;
	pcpp::IPAddress dstIp;

	this->proxyService->getPcapWriter()->writePacket(*parsedPacket.getRawPacketReadOnly());
	pcpp::Layer *networkLayer;
	if (const auto ipv4Layer = dynamic_cast<pcpp::IPv4Layer *>(parsedPacket.getFirstLayer()); ipv4Layer != nullptr) {
		srcIp = ipv4Layer->getSrcIPAddress();
		dstIp = ipv4Layer->getDstIPAddress();
		networkLayer = ipv4Layer;
	} else if (const auto ipv6Layer = dynamic_cast<pcpp::IPv6Layer *>(parsedPacket.getFirstLayer()); ipv6Layer != nullptr) {
		srcIp = ipv6Layer->getSrcIPAddress();
		dstIp = ipv6Layer->getDstIPAddress();
		networkLayer = ipv6Layer;
	} else {
		Logger::get().log("Received packet is not IPv4 or IPv6, ignoring");

		return true;
	}

	uint16_t srcPort{};
	uint16_t dstPort{};
	Protocol protocol = Protocol::UDP;

	if (auto tcpPacket = parsedPacket.getLayerOfType<pcpp::TcpLayer>()) {
		srcPort = tcpPacket->getSrcPort();
		dstPort = tcpPacket->getDstPort();
		protocol = Protocol::TCP;
	} else if (auto udpPacket = parsedPacket.getLayerOfType<pcpp::UdpLayer>()) {
		srcPort = udpPacket->getSrcPort();
		dstPort = udpPacket->getDstPort();
		protocol = Protocol::UDP;
	} else {
		Logger::get().log("Received unsupported transport layer");

		return true;
	}

	// Logger::Logger::get().log(
	// 	std::string("Received ") + (protocol ==
	// 		Protocol::TCP ? "TCP" : "UDP") + " packet from " + srcIp.toString() + ":" + std::to_string(srcPort) + " to " + dstIp.toString() + ":" + std::to_string(dstPort)
	// );

	if (const auto dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>()) {
		this->proxyService->getDnsManager()->processDns(*dnsLayer);
	}

	auto connection = this->connectionManager->find(getClientIp(), srcIp, dstIp, srcPort, dstPort, protocol);
	if (!connection) {
		if (protocol == Protocol::TCP) {
			if (auto tcpPacket = parsedPacket.getLayerOfType<pcpp::TcpLayer>()) {
				if (tcpPacket->getTcpHeader()->synFlag == 0) {
					Logger::get().log("Received non-SYN packet for non-existing connection, ignoring...");
					sendRst(srcIp, dstIp, srcPort, dstPort, isIpv6, tcpPacket->getTcpHeader()->ackNumber);

					return true;
				}
			}

			connection = std::make_shared<TcpConnection>(
				this->proxyService,
				shared_from_this(),
				srcIp,
				dstIp,
				srcPort,
				dstPort,
				this->proxyService->getNdpiStruct()
			);
		} else {
			connection = std::make_shared<UdpConnection>(
				this->proxyService,
				shared_from_this(),
				srcIp,
				dstIp,
				srcPort,
				dstPort,
				this->proxyService->getNdpiStruct()
			);
		}

		connection->setPcapWriter(this->proxyService->getPcapWriter());
		connection->setDnsManager(this->proxyService->getDnsManager());
		this->connectionManager->addConnection(connection);
	}

	connection->processPacketFromDevice(networkLayer);

	return true;
}

boost::asio::awaitable<void> Client::encryptOutgoingCoroutine() {
	while (clientSocket.is_open()) {
		while (!this->unencryptedQueueToDevice.empty()) {
			auto& data = this->unencryptedQueueToDevice.front();
			this->tlsConnection->send(std::span<const uint8_t>(data));
			this->unencryptedQueueToDevice.pop();
		}

		while (!this->encryptedQueueToDevice.empty()) {
			auto& data = this->encryptedQueueToDevice.front();
			auto len = co_await clientSocket.async_write_some(boost::asio::buffer(this->encryptedQueueToDevice), boost::asio::use_awaitable);
			if (len == 0) {
				break;
			}
			this->encryptedQueueToDevice.erase(this->encryptedQueueToDevice.begin(), this->encryptedQueueToDevice.begin() + len);
		}
	}
}

void Client::sendRst(pcpp::IPAddress srcIp, pcpp::IPAddress dstIp, uint16_t srcPort, uint16_t dstPort, bool isIpv6, uint32_t sequenceNumber) {
	pcpp::Layer *ipLayer = nullptr;
	if (isIpv6) {
		auto ipv6Layer = new pcpp::IPv6Layer(dstIp.getIPv6(), srcIp.getIPv6());
		ipv6Layer->getIPv6Header()->hopLimit = 64;
		ipv6Layer->getIPv6Header()->nextHeader = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;
		ipLayer = ipv6Layer;
	} else {
		auto ipv4Layer = new pcpp::IPv4Layer(dstIp.getIPv4(), srcIp.getIPv4());
		ipv4Layer->getIPv4Header()->timeToLive = 64;
		ipv4Layer->getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;
		ipLayer = ipv4Layer;
	}

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->rstFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = 0;
	tcpLayer->getTcpHeader()->sequenceNumber = sequenceNumber;
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(4096);

	pcpp::Packet rstPacket(50);
	rstPacket.addLayer(ipLayer, true);
	rstPacket.addLayer(tcpLayer, true);

	rstPacket.computeCalculateFields();

	pcpp::RawPacket rawPacket{};
	rawPacket.initWithRawData(
		rstPacket.getRawPacket()->getRawData(),
		rstPacket.getRawPacket()->getRawDataLen(),
		rstPacket.getRawPacket()->getPacketTimeStamp(),
		isIpv6 ? pcpp::LINKTYPE_IPV6 : pcpp::LINKTYPE_IPV4
	);

	getTlsConnection()->send(rstPacket.getRawPacketReadOnly()->getRawData(), rstPacket.getRawPacketReadOnly()->getRawDataLen());
}

const boost::asio::ip::tcp::socket & Client::getClientSocket() const {
	return clientSocket;
}

const pcpp::IPAddress & Client::getClientIp() const {
	return clientIp;
}

std::queue<std::vector<uint8_t>> & Client::getUnencryptedQueueToDevice() {
	return unencryptedQueueToDevice;
}

void Client::setTlsServer(std::shared_ptr<Botan::TLS::Server> tlsServer) {
	this->tlsConnection = std::move(tlsServer);
}

std::shared_ptr<Botan::TLS::Server> Client::getTlsConnection() {
	return tlsConnection;
}

void Client::enqueueData(std::vector<uint8_t> data) {
	unencryptedQueueToDevice.push(std::move(data));
}

std::vector<uint8_t> & Client::getUnencryptedQueueFromDevice() {
	return unencryptedQueueFromDevice;
}

std::vector<uint8_t> & Client::getEncryptedQueueToDevice() {
	return encryptedQueueToDevice;
}
