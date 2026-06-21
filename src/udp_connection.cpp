#include "udp_connection.h"

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/UdpLayer.h>

#include <utility>
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
	UdpConnection::gracefullyCloseRemoteSocket();
}

boost::asio::awaitable<void> UdpConnection::processPacketFromDevice(pcpp::Layer *networkLayer) {
	ZoneScoped;
	if (remoteSocketStatus != RemoteSocketStatus::ESTABLISHED) {
		co_await openSocket();
	}

	const auto udpLayer = dynamic_cast<pcpp::UdpLayer *>(networkLayer->getNextLayer());
	if (udpLayer == nullptr) {
		log("Received packet is not UDP");

		co_return;
	}

	processDpi(networkLayer->getDataPtr(0), networkLayer->getDataLen());
	++sentPacketCount;

	if (udpLayer->getLayerPayloadSize() == 0) {
		co_await sendDataToRemote(std::span<const uint8_t>{});
	} else {
		const auto data = udpLayer->getLayerPayload();
		{
			auto writeLock = getWriteLock();
			if (dataStream.size() < 1'000'000) {
				dataStream.insert(dataStream.end(), data, data + udpLayer->getLayerPayloadSize());
			}
		}
		co_await sendDataToRemote(std::span(data, udpLayer->getLayerPayloadSize()));
	}
}

boost::asio::awaitable<void> UdpConnection::openSocket() {
	ZoneScoped;

	try {
		this->remoteSocketStatus = RemoteSocketStatus::INITIATING;
		co_await this->destSocket.async_connect(
			boost::asio::ip::udp::endpoint(boost::asio::ip::make_address(this->dstIp.toString()), this->dstPort),
			boost::asio::use_awaitable
		);
	} catch (const boost::system::system_error& err) {
		log(std::format("Failed to connect: {}", err.what()));
		gracefullyCloseRemoteSocket();

		co_return;
	}

	setRemoteSocketStatus(RemoteSocketStatus::ESTABLISHED);
	this->connStartTime = std::chrono::system_clock::now();
}

boost::asio::awaitable<void> UdpConnection::sendDataToRemote(std::span<const uint8_t> data) {
	ZoneScoped;
	sentBytes += data.size();
	co_await this->destSocket.async_send(
		boost::asio::buffer(data),
		boost::asio::use_awaitable
	);
}

void UdpConnection::gracefullyCloseRemoteSocket() {
	ZoneScoped;

	if (remoteSocketStatus == RemoteSocketStatus::CLOSED && !this->destSocket.is_open()) {
		return;
	}

	this->destSocket.shutdown(boost::asio::socket_base::shutdown_both);
	this->destSocket.close();
	setRemoteSocketStatus(RemoteSocketStatus::CLOSED);
	logToFile();
}

boost::asio::awaitable<std::vector<uint8_t>> UdpConnection::read() {
	ZoneScoped;
	std::array<char, 16 * 1024> buffer{};

	const auto length = co_await this->destSocket.async_receive(boost::asio::buffer(buffer), boost::asio::use_awaitable);

	{
		ZoneScopedN("dataStreamWrite");
		auto writeLock = getWriteLock();
		if (dataStream.size() < 1'000'000) {
			dataStream.insert(dataStream.end(), buffer.begin(), buffer.begin() + length);
		}
	}
	receivedBytes += length;

	co_return std::vector<uint8_t>{buffer.begin(), buffer.begin() + length};
}

std::unique_ptr<pcpp::Packet> UdpConnection::encapsulateResponseDataToPacket(std::span<const uint8_t> data) {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto udpLayer = new pcpp::UdpLayer(dstPort, srcPort);
	auto payloadLayer = new pcpp::PayloadLayer(data.data(), data.size());

	auto udpPacket = std::make_unique<pcpp::Packet>(100 + data.size());
	udpPacket->addLayer(ipLayer, true);
	udpPacket->addLayer(udpLayer, true);
	udpPacket->addLayer(payloadLayer, true);

	udpPacket->computeCalculateFields();

	return udpPacket;
}

void UdpConnection::sendDataToDeviceSocket(std::span<const uint8_t> data) {
	ZoneScoped;
	size_t offset = 0;
	while (offset < data.size()) {
		const unsigned int length = std::min(offset + DEFAULT_MAX_SEGMENT_SIZE, data.size()) - offset;
		const auto packet = encapsulateResponseDataToPacket(std::span(data.begin() + offset, data.begin() + offset + length));
		if (!packet) {
			break;
		}

		if (const auto udpLayer = packet->getLayerOfType<pcpp::UdpLayer>(); udpLayer) {
			if (udpLayer->getDstPort() == 53 || udpLayer->getSrcPort() == 53) {
				pcpp::RawPacket rawPacket(packet->getRawPacket()->getRawData(), packet->getRawPacket()->getRawDataLen(), timeval{}, false,
					isIpv6() ? pcpp::LINKTYPE_IPV6 : pcpp::LINKTYPE_IPV4);
				pcpp::Packet p(&rawPacket);
				if (const auto dnsLayer = p.getLayerOfType<pcpp::DnsLayer>(); dnsLayer) {
					dnsManager->processDns(*dnsLayer);
				}
			}
		}

		sendToDeviceSocket(*packet);

		offset += length;
	}
}

void UdpConnection::forcefullyCloseAll() {
	gracefullyCloseRemoteSocket();
}

bool UdpConnection::canRemove() const {
	return !lastPacketSentTime.has_value() || std::chrono::system_clock::now() - lastPacketSentTime.value() > std::chrono::seconds(30);
}
