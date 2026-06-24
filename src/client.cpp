#include <boost/asio/completion_condition.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>

#include "client.h"

#include <iostream>

#include "connection_manager.h"
#include "dns_manager.h"
#include "file_writer.h"
#include "logger.h"
#include "protocol.h"
#include "proxy_service.h"
#include "tcp_connection.h"
#include "udp_connection.h"
#include "owned_parsed_packet.h"

Client::Client(
	std::weak_ptr<ProxyService> proxyService,
	boost::asio::ip::tcp::socket clientSocket,
	pcpp::IPAddress clientIp,
	uint16_t port
) : proxyService(std::move(proxyService)),
		connectionManager(std::make_shared<ConnectionManager>()),
		clientSocket(std::move(clientSocket)),
		clientIp(clientIp),
		port(port) {}

Client::~Client() = default;

boost::asio::awaitable<void> Client::handleClient() {
	co_await readTls();
}

boost::asio::awaitable<void> Client::readTls() {
	try {
		while (clientSocket.is_open()) {
			std::array<uint8_t, 16 * 1024> data{};
			auto len = co_await clientSocket.async_read_some(boost::asio::buffer(data), boost::asio::use_awaitable);
			this->tlsConnection->received_data(std::span<const uint8_t>(data.data(), len));
		}
	} catch (const boost::system::system_error & e) {
		if (e.code() == boost::asio::error::eof) {
			Logger::get().log("Client disconnected");
		} else {
			Logger::get().log(std::format("Error reading from client {}: {}", this->clientSocket.remote_endpoint().address().to_string(), e.what()));
		}
	}
}

boost::asio::awaitable<void> Client::writeTls() {
	if (this->writeTlsActive) {
		co_return;
	}

	this->writeTlsActive = true;

	while (!this->encryptedQueueToDevice.empty()) {
		const std::vector<uint8_t> chunk(this->encryptedQueueToDevice.begin(), this->encryptedQueueToDevice.end());
		std::size_t written = co_await boost::asio::async_write(
			this->clientSocket,
			boost::asio::buffer(chunk),
			boost::asio::use_awaitable
		);
		if (written == 0) {
			break;
		}
		this->encryptedQueueToDevice.erase(
			this->encryptedQueueToDevice.begin(),
			this->encryptedQueueToDevice.begin() + written
		);
	}

	this->writeTlsActive = false;
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

	auto packet = std::make_unique<OwnedParsedPacket>(
		std::move(packetBuffer),
		time,
		isIpv6
	);

	const auto proxyServicePtr = this->proxyService.lock();
	if (!proxyServicePtr) {
		return true;
	}

	pcpp::IPAddress srcIp;
	pcpp::IPAddress dstIp;

	proxyServicePtr->getPcapWriter()->writePacket(*packet->packet.getRawPacketReadOnly());
	if (const auto ipv4Layer = dynamic_cast<pcpp::IPv4Layer *>(packet->packet.getFirstLayer()); ipv4Layer != nullptr) {
		srcIp = ipv4Layer->getSrcIPAddress();
		dstIp = ipv4Layer->getDstIPAddress();
	} else if (const auto ipv6Layer = dynamic_cast<pcpp::IPv6Layer *>(packet->packet.getFirstLayer()); ipv6Layer != nullptr) {
		srcIp = ipv6Layer->getSrcIPAddress();
		dstIp = ipv6Layer->getDstIPAddress();
	} else {
		Logger::get().log("Received packet is not IPv4 or IPv6, ignoring");

		return true;
	}

	uint16_t srcPort{};
	uint16_t dstPort{};
	Protocol protocol = Protocol::UDP;

	if (auto tcpPacket = packet->packet.getLayerOfType<pcpp::TcpLayer>()) {
		srcPort = tcpPacket->getSrcPort();
		dstPort = tcpPacket->getDstPort();
		protocol = Protocol::TCP;
	} else if (auto udpPacket = packet->packet.getLayerOfType<pcpp::UdpLayer>()) {
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

	if (const auto dnsLayer = packet->packet.getLayerOfType<pcpp::DnsLayer>()) {
		proxyServicePtr->getDnsManager()->processDns(*dnsLayer);
	}

	auto connection = this->connectionManager->find(getClientIp(), srcIp, dstIp, srcPort, dstPort, protocol);
	if (!connection) {
		if (protocol == Protocol::TCP) {
			if (auto tcpPacket = packet->packet.getLayerOfType<pcpp::TcpLayer>()) {
				if (tcpPacket->getTcpHeader()->synFlag == 0) {
					Logger::get().log("Received non-SYN packet for non-existing connection, ignoring...");
					sendRst(srcIp, dstIp, srcPort, dstPort, isIpv6, tcpPacket->getTcpHeader()->ackNumber);

					return true;
				}
			}

			connection = std::make_shared<TcpConnection>(
				proxyServicePtr,
				shared_from_this(),
				srcIp,
				dstIp,
				srcPort,
				dstPort,
				proxyServicePtr->getNdpiStruct()
			);
		} else {
			connection = std::make_shared<UdpConnection>(
				proxyServicePtr,
				shared_from_this(),
				srcIp,
				dstIp,
				srcPort,
				dstPort,
				proxyServicePtr->getNdpiStruct()
			);
		}

		connection->setPcapWriter(proxyServicePtr->getPcapWriter());
		connection->setDnsManager(proxyServicePtr->getDnsManager());
		this->connectionManager->addConnection(connection);
	}

	boost::asio::co_spawn(
		clientSocket.get_executor(),
		[ptr = connection, packet = std::move(packet)] -> boost::asio::awaitable<void> {
			co_await ptr->processPacketFromDevice(packet->packet.getFirstLayer());
		},
		boost::asio::detached
	);

	return true;
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

bool Client::isWriteTlsActive() const {
	return writeTlsActive;
}
