#include "udp_connection.h"

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/UdpLayer.h>

#include <utility>

#include "packet_utils.h"

UdpConnection::UdpConnection(
	std::shared_ptr<Client> client,
	pcpp::IPAddress src_ip,
	pcpp::IPAddress dst_ip,
	uint16_t src_port,
	uint16_t dst_port,
	ndpi::ndpi_detection_module_struct *ndpiStruct
) : Connection(std::move(client), src_ip, dst_ip, src_port, dst_port, Protocol::UDP, ndpiStruct) {}

UdpConnection::~UdpConnection() {
	UdpConnection::gracefullyCloseRemoteSocket();
}

void UdpConnection::processPacketFromDevice(pcpp::Layer *networkLayer) {
	if (remoteSocketStatus != RemoteSocketStatus::ESTABLISHED) {
		openSocket();
	}

	const auto udpLayer = dynamic_cast<pcpp::UdpLayer *>(networkLayer->getNextLayer());
	if (udpLayer == nullptr) {
		log("Received packet is not UDP");

		return;
	}

	processDpi(networkLayer->getDataPtr(0), networkLayer->getDataLen());
	sentPacketCount++;

	if (udpLayer->getLayerPayloadSize() == 0) {
		sendDataToRemote(std::span<const uint8_t>{});
	} else {
		const auto data = udpLayer->getLayerPayload();
		{
			auto writeLock = getWriteLock();
			// dataStream.reserve(dataStream.size() + dataVec.size());
			if (dataStream.size() < 1'000'000) {
				dataStream.insert(dataStream.end(), data, data + udpLayer->getLayerPayloadSize());
			}
		}
		sendDataToRemote(std::span(data, udpLayer->getLayerPayloadSize()));
	}
}

void UdpConnection::openSocket() {
	if (isIpv6()) {
		socket = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	} else {
		socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}

	if (socket == INVALID_SOCKET) {
		log("socket() failed: " + std::to_string(WSAGetLastError()));
		gracefullyCloseRemoteSocket();

		return;
	}

	int res;
	if (isIpv6()) {
		ndpi::sockaddr_in6 addr{AF_INET6, htons(0), INADDR_ANY};
		res = bind(socket, (SOCKADDR *) &addr, sizeof(addr));
	} else {
		sockaddr_in addr{AF_INET, htons(0), INADDR_ANY};
		res = bind(socket, (SOCKADDR *) &addr, sizeof(addr));
	}

	if (res == SOCKET_ERROR) {
		log("bind() failed: " + std::to_string(WSAGetLastError()));
		gracefullyCloseRemoteSocket();

		return;
	}

	auto dstIpStr = dstIp.toString();
	if (isIpv6()) {
		auto destSockAddr = ndpi::sockaddr_in6{AF_INET6, htons(dstPort)};
		inet_pton(AF_INET6, dstIpStr.c_str(), &destSockAddr.sin6_addr);
		res = connect(socket, (SOCKADDR *) &destSockAddr, sizeof(destSockAddr));
	} else {
		auto destSockAddr = sockaddr_in{AF_INET, htons(dstPort)};
		destSockAddr.sin_addr.s_addr = inet_addr(dstIpStr.c_str());
		res = connect(socket, (SOCKADDR *) &destSockAddr, sizeof(destSockAddr));
	}

	if (res == SOCKET_ERROR) {
		log("connect() failed: " + std::to_string(WSAGetLastError()));
		gracefullyCloseRemoteSocket();

		return;
	}

	setRemoteSocketStatus(RemoteSocketStatus::ESTABLISHED);
}

void UdpConnection::sendDataToRemote(std::span<const uint8_t> data) {
	send(socket, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0);
}

void UdpConnection::gracefullyCloseRemoteSocket() {
	shutdown(socket, SD_BOTH);
	closeSocketAndInvalidate();
	setRemoteSocketStatus(RemoteSocketStatus::CLOSED);
}

std::vector<uint8_t> UdpConnection::read() {
	std::array<char, 65535> buffer{};

	u_long mode = 1;// Non-blocking mode
	ioctlsocket(socket, FIONBIO, &mode);
	int length = recv(socket, buffer.data(), buffer.size(), 0);
	const auto error = WSAGetLastError();

	mode = 0;	// Blocking mode
	ioctlsocket(socket, FIONBIO, &mode);

	if (length == SOCKET_ERROR) {
		if (error == WSAEWOULDBLOCK) {
			return {};
		}

		log("recv() failed: " + std::to_string(error));
		gracefullyCloseRemoteSocket();

		return {};
	}

	if (length == 0) {
		// Connection closed
		gracefullyCloseRemoteSocket();

		return {};
	}

	{
		auto writeLock = getWriteLock();
		// dataStream.reserve(dataStream.size() + length);
		if (dataStream.size() < 1'000'000) {
			dataStream.insert(dataStream.end(), buffer.begin(), buffer.begin() + length);
		}
		// dataStream.emplace_back(buffer.begin(), buffer.begin() + length);
	}

	return {buffer.begin(), buffer.begin() + length};
}

std::unique_ptr<pcpp::Packet> UdpConnection::encapsulateResponseDataToPacket(std::span<const uint8_t> data) {
	pcpp::Layer* ipLayer = buildIpLayer().release();

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
	size_t offset = 0;
	while (offset < data.size()) {
		const unsigned int length = std::min(offset + DEFAULT_MAX_SEGMENT_SIZE, data.size()) - offset;
		const auto packet = encapsulateResponseDataToPacket(std::span(data.begin() + offset, data.begin() + offset + length));
		if (!packet) {
			break;
		}

		// log(
		// 	"Sending to: " + originHostIp.toString() + ":" + std::to_string(originHostPort) + " " + PacketUtils::toString(*packet)
		// );

		if (const auto udpLayer = packet->getLayerOfType<pcpp::UdpLayer>(); udpLayer) {
			if (udpLayer->getDstPort() == 53 || udpLayer->getSrcPort() == 53) {
				pcpp::RawPacket rawPacket(packet->getRawPacket()->getRawData(), packet->getRawPacket()->getRawDataLen(), timeval{}, false, isIpv6() ? pcpp::LINKTYPE_IPV6 : pcpp::LINKTYPE_IPV4);
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
