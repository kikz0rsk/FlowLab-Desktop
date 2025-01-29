#include "udp_connection.h"

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/UdpLayer.h>

#include "packet_utils.h"

UdpConnection::UdpConnection(
	pcpp::IPAddress originHostIp,
	uint16_t originHostPort,
	pcpp::IPAddress src_ip,
	pcpp::IPAddress dst_ip,
	uint16_t src_port,
	uint16_t dst_port,
	SOCKET deviceSocket,
	ndpi::ndpi_detection_module_struct *ndpiStruct
) : Connection(originHostIp, originHostPort, src_ip, dst_ip, src_port, dst_port, Protocol::UDP, deviceSocket, ndpiStruct) {}

UdpConnection::~UdpConnection() {
	close();
}

void UdpConnection::processPacketFromDevice(pcpp::IPv4Layer *ipv4Layer) {
	if (remoteSocketStatus != RemoteSocketStatus::ESTABLISHED) {
		openSocket();
	}

	const auto udpLayer = dynamic_cast<pcpp::UdpLayer *>(ipv4Layer->getNextLayer());
	if (udpLayer == nullptr) {
		Logger::get().log("Received packet is not UDP");

		return;
	}

	processDpi(ipv4Layer->getDataPtr(0), ipv4Layer->getDataLen());
	sentPacketCount++;

	if (udpLayer->getLayerPayloadSize() == 0) {
		std::vector<uint8_t> vec = {};
		sendDataToRemote(vec);
	} else {
		const auto data = udpLayer->getLayerPayload();
		std::vector dataVec(data, data + udpLayer->getLayerPayloadSize());
		{
			auto writeLock = getWriteLock();
			dataStream.reserve(dataStream.size() + dataVec.size());
			dataStream.insert(dataStream.end(), dataVec.begin(), dataVec.end());
		}
		sendDataToRemote(dataVec);
	}
}

void UdpConnection::openSocket() {
	socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socket == INVALID_SOCKET) {
		Logger::get().log("socket() failed: " + std::to_string(WSAGetLastError()));

		return;
	}

	auto addr = sockaddr_in{AF_INET, htons(0), INADDR_ANY};
	int res = bind(socket, (SOCKADDR *) &addr, sizeof(sockaddr_in));
	if (res == SOCKET_ERROR) {
		Logger::get().log("bind() failed: " + std::to_string(WSAGetLastError()));

		return;
	}

	auto dstIpStr = dstIp.toString();
	auto destSockAddr = sockaddr_in{AF_INET, htons(dstPort)};
	destSockAddr.sin_addr.s_addr = inet_addr(dstIpStr.c_str());
	res = connect(socket, (SOCKADDR *) &destSockAddr, sizeof(destSockAddr));
	if (res == SOCKET_ERROR) {
		Logger::get().log("connect() failed: " + std::to_string(WSAGetLastError()));

		return;
	}

	remoteSocketStatus = RemoteSocketStatus::ESTABLISHED;
}

void UdpConnection::sendDataToRemote(std::vector<uint8_t> &data) {
	send(socket, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0);
}

void UdpConnection::close() {
	remoteSocketStatus = RemoteSocketStatus::CLOSED;
	closesocket(socket);
}

std::vector<uint8_t> UdpConnection::read() {
	std::array<char, 65535> buffer{};

	u_long mode = 1;// Non-blocking mode
	ioctlsocket(socket, FIONBIO, &mode);
	int length = recv(socket, buffer.data(), buffer.size(), 0);

	mode = 0;	// Blocking mode
	ioctlsocket(socket, FIONBIO, &mode);

	if (length == 0) {
		// Connection closed
		close();

		return {};
	}

	if (length == SOCKET_ERROR) {
		if (WSAGetLastError() == WSAEWOULDBLOCK) {
			return {};
		}

		Logger::get().log("recv() failed: " + std::to_string(WSAGetLastError()));
		close();

		return {};
	}

	{
		auto writeLock = getWriteLock();
		dataStream.reserve(dataStream.size() + length);
		dataStream.insert(dataStream.end(), buffer.begin(), buffer.begin() + length);
	}

	return {buffer.begin(), buffer.begin() + length};
}

std::unique_ptr<pcpp::Packet> UdpConnection::encapsulateResponseDataToPacket(const std::vector<uint8_t> &data) {
	auto ipLayer = new pcpp::IPv4Layer(dstIp.getIPv4(), srcIp.getIPv4());
	ipLayer->getIPv4Header()->timeToLive = 64;
	ipLayer->getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_UDP;

	auto udpLayer = new pcpp::UdpLayer(dstPort, srcPort);
	auto payloadLayer = new pcpp::PayloadLayer(data.data(), data.size());

	auto udpPacket = std::make_unique<pcpp::Packet>(100 + data.size());
	udpPacket->addLayer(ipLayer, true);
	udpPacket->addLayer(udpLayer, true);
	udpPacket->addLayer(payloadLayer, true);

	udpPacket->computeCalculateFields();

	return udpPacket;
}

void UdpConnection::sendDataToDeviceSocket(const std::vector<uint8_t> &data) {
	size_t offset = 0;
	while (offset < data.size()) {
		const unsigned int length = std::min(offset + MAX_SEGMENT_SIZE, data.size()) - offset;
		const auto packet = encapsulateResponseDataToPacket(std::vector(data.begin() + offset, data.begin() + offset + length));
		if (!packet) {
			break;
		}

		Logger::get().log(
			"Sending to: " + originHostIp.toString() + ":" + std::to_string(originHostPort) + " " + PacketUtils::toString(*packet)
		);

		if (const auto udpLayer = packet->getLayerOfType<pcpp::UdpLayer>(); udpLayer) {
			if (udpLayer->getDstPort() == 53 || udpLayer->getSrcPort() == 53) {
				pcpp::Packet p(100);
				pcpp::DnsLayer dns(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize(), udpLayer, &p);
				dnsManager->processDns(dns);
			}
		}

		sendToDeviceSocket(*packet);

		offset += length;
	}
}
