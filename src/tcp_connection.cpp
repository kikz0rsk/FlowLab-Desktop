#include "tcp_connection.h"

#include <random>
#include <iostream>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/PacketUtils.h>
#include <pcapplusplus/SystemUtils.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/SSLHandshake.h>
#include <pcapplusplus/SSLLayer.h>

#include "packet_utils.h"

TcpConnection::TcpConnection(
	pcpp::IPAddress originHostIp,
	uint16_t originHostPort,
	const pcpp::IPAddress &src_ip,
	const pcpp::IPAddress &dst_ip,
	uint16_t src_port,
	uint16_t dst_port,
	SOCKET deviceSocket,
	ndpi::ndpi_detection_module_struct *ndpiStruct
) :
	Connection(originHostIp, originHostPort, src_ip, dst_ip, src_port, dst_port, Protocol::TCP, deviceSocket, ndpiStruct) {}

TcpConnection::~TcpConnection() {
	closeRemoteSocket();
	if (connectingThread.joinable()) {
		connectingThread.join();
	}
}

void TcpConnection::resetState() {
	ackNumber = 0;
	ourSequenceNumber = 0;
	ourWindowSize = 65'535;
	remoteWindowSize = 65'535;
	finSequenceNumber = 0;
	unAckedBytes = 0;
	lastRemoteAckedNum = 0;
	windowSizeMultiplier = 1;
	shouldSendFinOnAckedEverything = false;
	remoteSocketStatus = RemoteSocketStatus::CLOSED;
	tcpStatus = TcpStatus::CLOSED;
}

void TcpConnection::closeRemoteSocket() {
	shutdown(socket, SD_BOTH);
	closesocket(socket);
	remoteSocketStatus = RemoteSocketStatus::CLOSED;
}

void TcpConnection::sendFinAck() {
	auto ipLayer = new pcpp::IPv4Layer(dstIp.getIPv4(), srcIp.getIPv4());
	ipLayer->getIPv4Header()->timeToLive = 64;
	ipLayer->getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->finFlag = 1;
	tcpLayer->getTcpHeader()->ackFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);

	pcpp::Packet packet(50);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDeviceSocket(packet);
}

void TcpConnection::sendSynAck() {
	auto ipLayer = new pcpp::IPv4Layer(dstIp.getIPv4(), srcIp.getIPv4());
	ipLayer->getIPv4Header()->timeToLive = 64;
	ipLayer->getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->synFlag = 1;
	tcpLayer->getTcpHeader()->ackFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);

	pcpp::TcpOptionBuilder mss(pcpp::TcpOptionEnumType::Mss, static_cast<uint16_t>(MAX_SEGMENT_SIZE));
	pcpp::TcpOptionBuilder winScale(pcpp::TcpOptionEnumType::Window, static_cast<uint16_t>(6));

	tcpLayer->addTcpOption(mss);
	tcpLayer->addTcpOption(winScale);

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDeviceSocket(packet);
}

void TcpConnection::processPacketFromDevice(pcpp::IPv4Layer *ipv4Layer) {
	auto tcpLayer = dynamic_cast<pcpp::TcpLayer *>(ipv4Layer->getNextLayer());
	auto packetSequenceNumber = pcpp::netToHost32(tcpLayer->getTcpHeader()->sequenceNumber);
	auto packetAckNumber = pcpp::netToHost32(tcpLayer->getTcpHeader()->ackNumber);
	if (remoteSocketStatus == RemoteSocketStatus::INITIATING) {
		Logger::get().log(
			"Waiting for connection to be established, throwing packet away: "
			+ ipv4Layer->getSrcIPAddress().toString()
			+ ":" + std::to_string(tcpLayer->getSrcPort())
			+ " -> " + ipv4Layer->getDstIPAddress().toString() + ":" + std::to_string(tcpLayer->getDstPort())
		);

		return;
	}

	processDpi(ipv4Layer->getDataPtr(0), ipv4Layer->getDataLen());
	sentPacketCount++;

	if (tcpLayer->getTcpHeader()->synFlag == 1) {
		resetState();
		// if (tcpStatus == TcpStatus::SYN_RECEIVED) {
		// 	Logger::get().log("Received duplicate SYN packet, ignoring...");
		// 	sendRst();
		//
		// 	return;
		// }

		ackNumber = packetSequenceNumber + 1;
		// std::random_device rd;
		// std::mt19937 gen(rd());
		// std::uniform_int_distribution<std::mt19937::result_type> distrib(1, std::numeric_limits<uint32_t>::max());
		ourSequenceNumber = 100;
		tcpStatus = TcpStatus::SYN_RECEIVED;

		const auto windowScaleOpt = tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Window);
		if (!windowScaleOpt.isNull()) {
			windowSizeMultiplier = 1 << windowScaleOpt.getValueAs<uint8_t>();
		}
		remoteWindowSize = pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) * windowSizeMultiplier;

		openSocket();

		return;
	}

	remoteWindowSize = pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) * windowSizeMultiplier;

	if (tcpLayer->getTcpHeader()->ackFlag == 1) {
		// const long long unAcked = ((static_cast<long long>(packetAckNumber) - 1) - static_cast<long long>(ourSequenceNumber.load()));
		if (packetAckNumber >= lastRemoteAckedNum) {
			lastRemoteAckedNum = packetAckNumber;
		}
		const long long unAcked = static_cast<long long>(ourSequenceNumber.load()) - static_cast<long long>(lastRemoteAckedNum) + 1;
		unAckedBytes = unAcked > 0 ? unAcked : 0;
		Logger::get().log("Unacked bytes: " + std::to_string(unAckedBytes));
		if (tcpStatus == TcpStatus::SYN_RECEIVED) {
			tcpStatus = TcpStatus::ESTABLISHED;
		} else if (tcpStatus == TcpStatus::FIN_WAIT_1 && lastRemoteAckedNum > finSequenceNumber) {
			tcpStatus = TcpStatus::FIN_WAIT_2;
		} else if (tcpStatus == TcpStatus::CLOSE_WAIT) {
			closeRemoteSocket();
			tcpStatus = TcpStatus::CLOSED;
		}

		if (packetAckNumber != ourSequenceNumber) {
			// remote hasn't acked all of our messages yet
			// if (tcpLayer->getTcpHeader()->rstFlag == 1) {
			// 	closeRemoteSocket();
			// 	resetState();
			//
			// 	return;
			// }

			Logger::get().log(
				"Packet ack number does not match our sequence number, this packet ack="
				+ std::to_string(packetAckNumber)
				+ ", expected="
				+ std::to_string(ourSequenceNumber)
			);
		}
	}

	if (packetSequenceNumber != ackNumber) {
		// packet is out of order
		if (tcpLayer->getTcpHeader()->rstFlag == 1) {
			closeRemoteSocket();
			tcpStatus = TcpStatus::CLOSED;

			return;
		}

		Logger::get().log(
			"Received unexpected packet, this packet seq="
			+ std::to_string(packetSequenceNumber)
			+ ", expected="
			+ std::to_string(ackNumber)
		);
		sendAck();

		return;
	}

	const unsigned int dataSize = tcpLayer->getLayerPayloadSize();
	if (dataSize > 0) {
		const auto dataPtr = tcpLayer->getLayerPayload();
		{
			auto writeLock = getWriteLock();
			dataStream.reserve(dataStream.size() + dataSize);
			dataStream.insert(dataStream.end(), dataPtr, dataPtr + dataSize);
		}

		auto vec = std::vector(dataPtr, dataPtr + tcpLayer->getLayerPayloadSize());
		sendDataToRemote(vec);
	}

	ackNumber = packetSequenceNumber;
	if (dataSize > 0) {
		ackNumber += dataSize;
		sendAck();
	}

	if (tcpLayer->getTcpHeader()->rstFlag == 1) {
		closeRemoteSocket();
		tcpStatus = TcpStatus::CLOSED;

		return;
	}

	if (tcpLayer->getTcpHeader()->finFlag == 1) {
		if (tcpStatus == TcpStatus::FIN_WAIT_2) {
			ackNumber += 1;
			sendAck();

			closeRemoteSocket();
			tcpStatus = TcpStatus::CLOSED;

			return;
		} else if (tcpStatus == TcpStatus::ESTABLISHED) {
			Logger::get().log("Remote side is initiating TCP close");
			if (unAckedBytes > 0) {
				ackNumber += 1;
				sendAck();
				shouldSendFinOnAckedEverything = true;
			} else {
				ackNumber += 1;
				sendFinAck();
				finSequenceNumber = ourSequenceNumber.load();
				ourSequenceNumber += 1;
				tcpStatus = TcpStatus::CLOSE_WAIT;
			}

			return;
		}
	}

	if (
		tcpLayer->getTcpHeader()->ackFlag == 1 && unAckedBytes == 0 && shouldSendFinOnAckedEverything
		&& tcpStatus != TcpStatus::FIN_WAIT_1 && tcpStatus != TcpStatus::FIN_WAIT_2 && tcpStatus != TcpStatus::CLOSE_WAIT
	) {
		sendFinAck();
		tcpStatus = TcpStatus::FIN_WAIT_1;
		finSequenceNumber = ourSequenceNumber.load();
		ourSequenceNumber += 1;
	}
}

void TcpConnection::openSocket() {
	if (remoteSocketStatus == RemoteSocketStatus::ESTABLISHED) {
		closeRemoteSocket();
	}

	socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socket == INVALID_SOCKET) {
		std::cerr << "socket() failed: " << WSAGetLastError() << std::endl;

		return;
	}

	auto addr = sockaddr_in{AF_INET, htons(0), INADDR_ANY};
	int res = bind(socket, (SOCKADDR *) &addr, sizeof(sockaddr_in));
	if (res == SOCKET_ERROR) {
		std::cerr << "bind() failed: " << WSAGetLastError() << std::endl;

		return;
	}
	const bool nodelay = true;
	setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&nodelay), sizeof(nodelay));
	u_long mode = 1;// Non-blocking mode
	ioctlsocket(socket, FIONBIO, &mode);
	auto dstIpStr = dstIp.toString();
	auto destSockAddr = sockaddr_in{AF_INET, htons(dstPort)};
	destSockAddr.sin_addr.s_addr = inet_addr(dstIpStr.c_str());
	if (connectingThread.joinable()) {
		connectingThread.join();
	}
	remoteSocketStatus = RemoteSocketStatus::INITIATING;
	res = connect(socket, (SOCKADDR *) &destSockAddr, sizeof(destSockAddr));
	if (res == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
		std::cerr << "connect() failed: " << WSAGetLastError() << std::endl;
		sendRst();
		remoteSocketStatus = RemoteSocketStatus::CLOSED;

		return;
	}
}

void TcpConnection::sendAck() {
	auto ipLayer = new pcpp::IPv4Layer(dstIp.getIPv4(), srcIp.getIPv4());
	ipLayer->getIPv4Header()->timeToLive = 64;
	ipLayer->getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->ackFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);

	pcpp::Packet packet(50);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDeviceSocket(packet);
}

void TcpConnection::sendDataToRemote(std::vector<uint8_t> &data) {
	send(socket, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0);
}

std::vector<uint8_t> TcpConnection::read() {
	if (remoteSocketStatus != RemoteSocketStatus::ESTABLISHED) {
		return {};
	}

	long long bytesToRead = static_cast<long long>(this->remoteWindowSize) - static_cast<long long>(unAckedBytes) - 1000;
	if (bytesToRead <= 0) {
		return {};
	}

	// if (unAckedBytes >= 10'000 || (unAckedBytes > 0 && unAckedBytes >= remoteWindowSize)) {
	// 	Logger::get().log("Delaying read due to unacked bytes: " + std::to_string(unAckedBytes) + " " + std::to_string(remoteWindowSize));
	//
	// 	return {};
	// }

	std::vector<char> buffer(bytesToRead);

	u_long mode = 1;// Non-blocking mode
	ioctlsocket(socket, FIONBIO, &mode);
	const int length = recv(socket, buffer.data(), static_cast<int>(buffer.size()), 0);

	mode = 0;	// Blocking mode
	ioctlsocket(socket, FIONBIO, &mode);

	if (length == 0) {
		// Connection closed
		if (
			tcpStatus == TcpStatus::FIN_WAIT_1
			|| tcpStatus == TcpStatus::FIN_WAIT_2 || tcpStatus == TcpStatus::CLOSE_WAIT || shouldSendFinOnAckedEverything
		) {
			return {};
		}

		if (unAckedBytes > 0) {
			Logger::get().log("Waiting for ack on everything before closing connection");
			shouldSendFinOnAckedEverything = true;
		} else {
			Logger::get().log("We are initiating TCP close");
			sendFinAck();
			tcpStatus = TcpStatus::FIN_WAIT_1;
			finSequenceNumber = ourSequenceNumber.load();
			ourSequenceNumber += 1;
		}

		return {};
	}

	if (length == SOCKET_ERROR) {
		const int error = WSAGetLastError();
		if (error == WSAEWOULDBLOCK) {
			return {};
		}

		Logger::get().log("recv() failed: " + error);
		closeRemoteSocket();
		sendRst();
		tcpStatus = TcpStatus::CLOSED;

		return {};
	}

	// {
	// 	auto writeLock = getWriteLock();
	// 	dataStream.reserve(dataStream.size() + length);
	// 	dataStream.insert(dataStream.end(), buffer.begin(), buffer.begin() + length);
	// }

	return {buffer.begin(), buffer.begin() + length};
}

void TcpConnection::writeEvent() {
	if (this->remoteSocketStatus == RemoteSocketStatus::INITIATING) {
		remoteSocketStatus = RemoteSocketStatus::ESTABLISHED;
		u_long mode = 0;// Blocking mode
		ioctlsocket(socket, FIONBIO, &mode);
		sendSynAck();
		ourSequenceNumber += 1;
	}
}

void TcpConnection::exceptionEvent() {
	if (this->remoteSocketStatus == RemoteSocketStatus::INITIATING) {
		u_long mode = 0; // Blocking mode
		ioctlsocket(socket, FIONBIO, &mode);
		sendRst();
		closeRemoteSocket();
		tcpStatus = TcpStatus::CLOSED;
	}
}

std::unique_ptr<pcpp::Packet> TcpConnection::encapsulateResponseDataToPacket(const std::vector<uint8_t> &data) {
	auto ipLayer = new pcpp::IPv4Layer(dstIp.getIPv4(), srcIp.getIPv4());
	ipLayer->getIPv4Header()->timeToLive = 64;
	ipLayer->getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->ackFlag = 1;
	tcpLayer->getTcpHeader()->pshFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);
	auto payloadLayer = new pcpp::PayloadLayer(data.data(), data.size());

	auto tcpPacket = std::make_unique<pcpp::Packet>(data.size() + 100);
	tcpPacket->addLayer(ipLayer, true);
	tcpPacket->addLayer(tcpLayer, true);
	tcpPacket->addLayer(payloadLayer, true);

	tcpPacket->computeCalculateFields();

	return tcpPacket;
}

void TcpConnection::sendDataToDeviceSocket(const std::vector<uint8_t> &data) {
	size_t offset = 0;
	while (offset < data.size()) {
		const unsigned int length = std::min(offset + MAX_SEGMENT_SIZE, data.size()) - offset;
		const bool isLast = offset + length == data.size();
		const auto packet = encapsulateResponseDataToPacket(std::vector(data.begin() + offset, data.begin() + offset + length));
		if (!packet) {
			break;
		}
		if (isLast) {
			packet->getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->pshFlag = 1;
		}

		Logger::get().log(
			"Sending to: " + originHostIp.toString() + ":" + std::to_string(originHostPort) + " " + PacketUtils::toString(*packet)
		);

		sendToDeviceSocket(*packet);

		ourSequenceNumber += length;
		unAckedBytes += length;
		offset += length;
	}
}

unsigned int TcpConnection::getAckNumber() const {
	return ackNumber;
}

std::atomic_uint32_t & TcpConnection::getOurSequenceNumber() {
	return ourSequenceNumber;
}

void TcpConnection::sendRst() {
	auto ipLayer = new pcpp::IPv4Layer(dstIp.getIPv4(), srcIp.getIPv4());
	ipLayer->getIPv4Header()->timeToLive = 64;
	ipLayer->getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->rstFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);

	pcpp::Packet packet(50);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDeviceSocket(packet);
}

unsigned long TcpConnection::getBytesAvailable(SOCKET socket) {
	unsigned long bytes;
	ioctlsocket(socket,FIONREAD, &bytes);

	return bytes;
}

TcpStatus TcpConnection::getTcpStatus() const {
	return tcpStatus.load();
}

void TcpConnection::setTcpStatus(TcpStatus tcpStatus) {
	this->tcpStatus = tcpStatus;
}
