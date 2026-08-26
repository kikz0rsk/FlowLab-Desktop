#include "udp_connection.h"

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/UdpLayer.h>

#include <utility>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <pcapplusplus/DnsLayer.h>
#include <tracy/Tracy.hpp>

#include "dns_manager.h"
#include "packet_utils.h"
#include "proxy_service.h"

UdpConnection::UdpConnection(
	std::shared_ptr<ProxyService> proxyService,
	std::shared_ptr<Client> client,
	pcpp::IPAddress src_ip,
	pcpp::IPAddress dst_ip,
	uint16_t src_port,
	uint16_t dst_port,
	ndpi::ndpi_detection_module_struct *ndpiStruct
) : Connection(proxyService, std::move(client), src_ip, dst_ip, src_port, dst_port, Protocol::UDP, ndpiStruct), destSocket(proxyService->getIoContext()) {}

UdpConnection::~UdpConnection() {
	UdpConnection::closeSocketSoft();
}

boost::asio::awaitable<void> UdpConnection::processPacketFromDevice(pcpp::Layer *networkLayer) {
	ZoneScoped;
	if (remoteSocketStatus != RemoteSocketStatus::ESTABLISHED) {
		co_await openSocket();
	}

	const auto* udpLayer = dynamic_cast<pcpp::UdpLayer *>(networkLayer->getNextLayer());
	if (udpLayer == nullptr) {
		log("Received packet is not UDP");

		co_return;
	}

	processDpi(networkLayer->getDataPtr(0), networkLayer->getDataLen());
	++sentPacketCount;

	if (udpLayer->getLayerPayloadSize() == 0) {
		co_await sendDataToRemote(std::span<const uint8_t>{});
	} else {
		const auto* data = udpLayer->getLayerPayload();
		co_await sendDataToRemote(std::span(data, udpLayer->getLayerPayloadSize()));
	}
}

boost::asio::awaitable<void> UdpConnection::openSocket() {
	ZoneScoped;

	try {
		setRemoteSocketStatus(RemoteSocketStatus::INITIATING);
		co_await this->destSocket.async_connect(
			boost::asio::ip::udp::endpoint(boost::asio::ip::make_address(this->dstIp.toString()), this->dstPort),
			boost::asio::use_awaitable
		);

		boost::asio::co_spawn(this->proxyService->getIoContext(), [this, ptr = shared_from_this()] -> boost::asio::awaitable<void> {
			co_await this->readLoop();
		}, boost::asio::detached);
	} catch (const boost::system::system_error& err) {
		log(std::format("Failed to connect: {}", err.what()));
		closeSocketSoft();

		co_return;
	}

	setRemoteSocketStatus(RemoteSocketStatus::ESTABLISHED);
	this->connStartTime = std::chrono::system_clock::now();
}

boost::asio::awaitable<void> UdpConnection::readLoop() {
	try {
		while (this->destSocket.is_open()) {
			co_await read();
		}
	} catch (...) {}
	log("readLoop exited");
}

boost::asio::awaitable<void> UdpConnection::sendDataToRemote(std::span<const uint8_t> data) {
	ZoneScoped;
	sentBytes += data.size();
	co_await this->destSocket.async_send(
		boost::asio::buffer(data),
		boost::asio::use_awaitable
	);
}

void UdpConnection::closeSocketSoft() {
	ZoneScoped;

	if (remoteSocketStatus == RemoteSocketStatus::CLOSED && !this->destSocket.is_open()) {
		return;
	}

	try {
		this->destSocket.shutdown(boost::asio::socket_base::shutdown_both);
		this->destSocket.close();
	} catch (const boost::system::system_error& e) {
		log(std::format("Error closing socket: {}", e.what()));
	}

	setRemoteSocketStatus(RemoteSocketStatus::CLOSED);
	logToFile();
}

boost::asio::awaitable<void> UdpConnection::read() {
	ZoneScoped;
	std::array<uint8_t, BUFFER_SIZE> buffer{};

	unsigned long long length;
	try {
		length = co_await this->destSocket.async_receive(boost::asio::buffer(buffer), boost::asio::use_awaitable);
	} catch (const boost::system::system_error& err) {
		closeSocketSoft();

		throw;
	}

	receivedBytes += length;

	sendDataToDevice(std::span(buffer.begin(), length));
}

std::unique_ptr<pcpp::Packet> UdpConnection::encapsulateResponseDataToPacket(std::span<const uint8_t> data) {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto* udpLayer = new pcpp::UdpLayer(dstPort, srcPort);
	auto* payloadLayer = new pcpp::PayloadLayer(data.data(), data.size());

	auto udpPacket = std::make_unique<pcpp::Packet>(100 + data.size());
	udpPacket->addLayer(ipLayer, true);
	udpPacket->addLayer(udpLayer, true);
	udpPacket->addLayer(payloadLayer, true);

	udpPacket->computeCalculateFields();

	return udpPacket;
}

void UdpConnection::sendDataToDevice(std::span<const uint8_t> data) {
	ZoneScoped;
	size_t offset = 0;
	while (offset < data.size()) {
		const unsigned int length = std::min(offset + DEFAULT_MAX_SEGMENT_SIZE, data.size()) - offset;
		const auto packet = encapsulateResponseDataToPacket(std::span(data.begin() + offset, data.begin() + offset + length));
		if (!packet) {
			break;
		}

		if (const auto* udpLayer = packet->getLayerOfType<pcpp::UdpLayer>(); udpLayer) {
			if (udpLayer->getDstPort() == 53 || udpLayer->getSrcPort() == 53) {
				pcpp::RawPacket rawPacket(packet->getRawPacket()->getRawData(), packet->getRawPacket()->getRawDataLen(), timeval{}, false,
					isIpv6() ? pcpp::LINKTYPE_IPV6 : pcpp::LINKTYPE_IPV4);
				const pcpp::Packet p(&rawPacket);
				if (const auto* dnsLayer = p.getLayerOfType<pcpp::DnsLayer>(); dnsLayer) {
					dnsManager->processDns(*dnsLayer);
				}
			}
		}

		sendToDevice(*packet);

		offset += length;
	}
}

void UdpConnection::closeAllForce() {
	closeSocketSoft();
}

bool UdpConnection::canRemove() const {
	return !lastPacketSentTime.has_value() || std::chrono::system_clock::now() - lastPacketSentTime.value() > std::chrono::seconds(30);
}
