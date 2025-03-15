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
#include <tracy/Tracy.hpp>
#include <utility>

#include "logger.h"
#include "packet_utils.h"

TcpConnection::TcpConnection(
	std::shared_ptr<Client> client,
	const pcpp::IPAddress &src_ip,
	const pcpp::IPAddress &dst_ip,
	uint16_t src_port,
	uint16_t dst_port,
	ndpi::ndpi_detection_module_struct *ndpiStruct
) :
	Connection(std::move(client), src_ip, dst_ip, src_port, dst_port, Protocol::TCP, ndpiStruct) {}

TcpConnection::~TcpConnection() {
	TcpConnection::gracefullyCloseRemoteSocket();
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
	maxSegmentSize = DEFAULT_MAX_SEGMENT_SIZE;
	shouldSendFinOnAckedEverything = false;
	setRemoteSocketStatus(RemoteSocketStatus::CLOSED);
	setTcpStatus(TcpStatus::CLOSED);
}

void TcpConnection::gracefullyCloseRemoteSocket() {
	ZoneScoped;

	if (this->remoteSocketStatus == RemoteSocketStatus::CLOSED) {
		return;
	}

	shutdown(socket, SD_BOTH);
	closeSocketAndInvalidate();
	setRemoteSocketStatus(RemoteSocketStatus::CLOSED);
}

void TcpConnection::sendFinAck() {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->finFlag = 1;
	tcpLayer->getTcpHeader()->ackFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDeviceSocket(packet);
}

void TcpConnection::sendSynAck() {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->synFlag = 1;
	tcpLayer->getTcpHeader()->ackFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);

	pcpp::TcpOptionBuilder mss(pcpp::TcpOptionEnumType::Mss, static_cast<uint16_t>(DEFAULT_MAX_SEGMENT_SIZE));
	pcpp::TcpOptionBuilder winScale(pcpp::TcpOptionEnumType::Window, static_cast<uint8_t>(8));
	pcpp::TcpOptionBuilder noop(pcpp::TcpOptionBuilder::NopEolOptionEnumType::Nop);

	tcpLayer->addTcpOption(winScale);
	tcpLayer->addTcpOption(mss);
	tcpLayer->addTcpOption(noop);

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDeviceSocket(packet);
}

void TcpConnection::processPacketFromDevice(pcpp::Layer *networkLayer) {
	ZoneScoped;
	auto tcpLayer = dynamic_cast<pcpp::TcpLayer *>(networkLayer->getNextLayer());
	auto packetSequenceNumber = pcpp::netToHost32(tcpLayer->getTcpHeader()->sequenceNumber);
	auto packetAckNumber = pcpp::netToHost32(tcpLayer->getTcpHeader()->ackNumber);
	if (remoteSocketStatus == RemoteSocketStatus::INITIATING) {
		log("Waiting for connection to be established: " + tcpLayer->toString());

		auto dstIpStr = dstIp.toString();
		int res;
		if (isIpv6()) {
			sockaddr_in6 destSockAddr{};
			destSockAddr.sin6_family = AF_INET6;
			destSockAddr.sin6_port = htons(dstPort);
			inet_pton(AF_INET6, dstIpStr.c_str(), &destSockAddr.sin6_addr);
			res = connect(socket, (SOCKADDR *) &destSockAddr, sizeof(destSockAddr));
		} else {
			sockaddr_in destSockAddr{};
			destSockAddr.sin_family = AF_INET;
			destSockAddr.sin_port = htons(dstPort);
			destSockAddr.sin_addr.s_addr = inet_addr(dstIpStr.c_str());
			res = connect(socket, (SOCKADDR *) &destSockAddr, sizeof(destSockAddr));
		}
		const auto errCode = getLastSocketError();
		if (res == SOCKET_ERROR) {
			if (errCode == WSAEWOULDBLOCK || errCode == WSAEINPROGRESS) {
				log("In progress");
			} else if (errCode == WSAEISCONN) {
				log("Connected");
				writeEvent();
			} else {
				log("Connect failed: " + std::to_string(getLastSocketError()));
			}
		}

		return;
	}

	processDpi(networkLayer->getDataPtr(0), networkLayer->getDataLen());
	++sentPacketCount;

	if (tcpLayer->getTcpHeader()->synFlag == 1) {
		resetState();
		// if (tcpStatus == TcpStatus::SYN_RECEIVED) {
		// 	log("Received duplicate SYN packet, ignoring...");
		// 	sendRst();
		//
		// 	return;
		// }

		ackNumber = packetSequenceNumber + 1;
		// std::random_device rd;
		// std::mt19937 gen(rd());
		// std::uniform_int_distribution<std::mt19937::result_type> distrib(1, std::numeric_limits<uint32_t>::max());
		ourSequenceNumber = 100;
		setTcpStatus(TcpStatus::SYN_RECEIVED);

		const auto windowScaleOpt = tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Window);
		if (!windowScaleOpt.isNull()) {
			windowSizeMultiplier = 1 << windowScaleOpt.getValueAs<uint8_t>();
		}

		const auto mssOpt = tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Mss);
		if (!mssOpt.isNull()) {
			maxSegmentSize = pcpp::netToHost16(mssOpt.getValueAs<uint16_t>());
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
		const long long unAcked = static_cast<long long>(ourSequenceNumber.load()) - static_cast<long long>(lastRemoteAckedNum);
		unAckedBytes = unAcked > 0 ? unAcked : 0;
		// log("Unacked bytes: " + std::to_string(unAckedBytes));
		if (tcpStatus == TcpStatus::SYN_RECEIVED) {
			setTcpStatus(TcpStatus::ESTABLISHED);
		} else if (tcpStatus == TcpStatus::FIN_WAIT_1 && lastRemoteAckedNum > finSequenceNumber) {
			setTcpStatus(TcpStatus::FIN_WAIT_2);
		} else if (tcpStatus == TcpStatus::CLOSE_WAIT && lastRemoteAckedNum > finSequenceNumber) {
			gracefullyCloseRemoteSocket();
			setTcpStatus(TcpStatus::CLOSED);
		}
	}

	if (packetSequenceNumber != ackNumber) {
		// packet is out of order
		if (tcpLayer->getTcpHeader()->rstFlag == 1) {
			forcefullyCloseAll();

			return;
		}

		log(
			"Received unexpected packet, this packet seq="
			+ std::to_string(packetSequenceNumber)
			+ ", expected="
			+ std::to_string(ackNumber)
		);
		sendAck();

		return;
	}

	const size_t dataSize = tcpLayer->getLayerPayloadSize();
	if (dataSize > 0) {
		const auto dataPtr = tcpLayer->getLayerPayload();
		{
			ZoneScopedN("dataStreamWrite");
			auto writeLock = getWriteLock();
			// dataStream.reserve(dataStream.size() + dataSize);
			if (dataStream.size() < 1'000'000) {
				dataStream.insert(dataStream.end(), dataPtr, dataPtr + dataSize);
			}

			// dataStream.emplace_back(dataPtr, dataPtr + dataSize);
		}

		// auto vec = std::vector(dataPtr, dataPtr + tcpLayer->getLayerPayloadSize());
		sendDataToRemote(std::span(dataPtr, dataSize));
	}

	ackNumber = packetSequenceNumber;
	if (dataSize > 0) {
		ackNumber += dataSize;
		sendAck();
	}

	if (tcpLayer->getTcpHeader()->rstFlag == 1) {
		forcefullyCloseAll();

		return;
	}

	if (tcpLayer->getTcpHeader()->finFlag == 1) {
		if (tcpStatus == TcpStatus::FIN_WAIT_2) {
			ackNumber += 1;
			sendAck();

			gracefullyCloseRemoteSocket();
			setTcpStatus(TcpStatus::CLOSED);

			return;
		} else if (tcpStatus == TcpStatus::ESTABLISHED) {
			log("Remote side is initiating TCP close");
			if (unAckedBytes > 0) {
				ackNumber += 1;
				sendAck();
				shouldSendFinOnAckedEverything = true;
			} else {
				ackNumber += 1;
				sendFinAck();
				finSequenceNumber = ourSequenceNumber.load();
				ourSequenceNumber += 1;
				setTcpStatus(TcpStatus::CLOSE_WAIT);
			}

			return;
		}
	}

	if (
		tcpLayer->getTcpHeader()->ackFlag == 1 && unAckedBytes == 0 && shouldSendFinOnAckedEverything
		&& tcpStatus != TcpStatus::FIN_WAIT_1 && tcpStatus != TcpStatus::FIN_WAIT_2 && tcpStatus != TcpStatus::CLOSE_WAIT
	) {
		sendFinAck();
		setTcpStatus(TcpStatus::FIN_WAIT_1);
		finSequenceNumber = ourSequenceNumber.load();
		ourSequenceNumber += 1;
	}
}

void TcpConnection::openSocket() {
	ZoneScoped;
	if (remoteSocketStatus == RemoteSocketStatus::ESTABLISHED) {
		gracefullyCloseRemoteSocket();
	}

	if (isIpv6()) {
		socket = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	} else {
		socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}

	if (socket == INVALID_SOCKET) {
		std::cerr << "socket() failed: " << getLastSocketError() << std::endl;
		sendRst();
		setRemoteSocketStatus(RemoteSocketStatus::CLOSED);

		return;
	}

	int res;
	if (isIpv6()) {
		sockaddr_in6 addr{};
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(0);
		addr.sin6_addr = in6addr_any;
		res = bind(socket, (SOCKADDR *) &addr, sizeof(addr));
	} else {
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(0);
		addr.sin_addr.s_addr = INADDR_ANY;
		res = bind(socket, (SOCKADDR *) &addr, sizeof(addr));
	}

	if (res == SOCKET_ERROR) {
		std::cerr << "bind() failed: " << getLastSocketError() << std::endl;
		sendRst();
		setRemoteSocketStatus(RemoteSocketStatus::CLOSED);

		return;
	}

	const bool nodelay = true;
	setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&nodelay), sizeof(nodelay));
	u_long mode = 1;// Non-blocking mode
	ioctlSocket(socket, FIONBIO, &mode);

	auto dstIpStr = dstIp.toString();

	if (isIpv6()) {
		sockaddr_in6 destSockAddr{};
		destSockAddr.sin6_family = AF_INET6;
		destSockAddr.sin6_port = htons(dstPort);
		inet_pton(AF_INET6, dstIpStr.c_str(), &destSockAddr.sin6_addr);
		setRemoteSocketStatus(RemoteSocketStatus::INITIATING);
		res = connect(socket, (SOCKADDR *) &destSockAddr, sizeof(destSockAddr));
	} else {
		sockaddr_in destSockAddr{};
		destSockAddr.sin_family = AF_INET;
		destSockAddr.sin_port = htons(dstPort);
		destSockAddr.sin_addr.s_addr = inet_addr(dstIpStr.c_str());
		setRemoteSocketStatus(RemoteSocketStatus::INITIATING);
		res = connect(socket, (SOCKADDR *) &destSockAddr, sizeof(destSockAddr));
	}

	if (res == SOCKET_ERROR) {
		const auto errCode = getLastSocketError();
		if (errCode == WSAEWOULDBLOCK) {
			return;
		}
		if (errCode == WSAEISCONN) {
			if (remoteSocketStatus != RemoteSocketStatus::ESTABLISHED) {
				setRemoteSocketStatus(RemoteSocketStatus::ESTABLISHED);
				sendSynAck();
				ourSequenceNumber += 1;
			}

			return;
		}
		if (errCode == WSAEALREADY) {
			return;
		}

		std::cerr << "connect() failed: " << errCode << std::endl;
		sendRst();
		gracefullyCloseRemoteSocket();
	} else {
		Logger::get().log("Connected to remote socket");
	}
}

void TcpConnection::sendAck() {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->ackFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDeviceSocket(packet);
}

void TcpConnection::sendDataToRemote(std::span<const uint8_t> data) {
	ZoneScoped;
	sentBytes += data.size();
	int res = send(socket, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0);
	if (res != SOCKET_ERROR && res != data.size()) {
		log("send() failed to send all data");
	}
}

std::vector<uint8_t> TcpConnection::read() {
	ZoneScoped;
	if (remoteSocketStatus != RemoteSocketStatus::ESTABLISHED) {
		return {};
	}

	long long bytesToRead = static_cast<long long>(this->remoteWindowSize) - static_cast<long long>(unAckedBytes) - 2 * static_cast<long long>(maxSegmentSize);
	if (bytesToRead <= 0) {
		return {};
	}

	// bytesToRead = bytesToRead > 30'000 ? 30'000 : bytesToRead;
	bytesToRead = bytesToRead < maxSegmentSize ? bytesToRead : maxSegmentSize;
	log("bytesToRead: " + std::to_string(bytesToRead));
	// if (unAckedBytes >= 10'000 || (unAckedBytes > 0 && unAckedBytes >= remoteWindowSize)) {
	// 	log("Delaying read due to unacked bytes: " + std::to_string(unAckedBytes) + " " + std::to_string(remoteWindowSize));
	//
	// 	return {};
	// }

	std::vector<char> buffer(bytesToRead);

	u_long mode = 1;// Non-blocking mode
	ioctlSocket(socket, FIONBIO, &mode);
	const int length = recv(socket, buffer.data(), static_cast<int>(buffer.size()), 0);
	const int error = getLastSocketError();
	mode = 0;	// Blocking mode
	ioctlSocket(socket, FIONBIO, &mode);
	// if (res == SOCKET_ERROR) {
	// 	const auto errCode = getLastSocketError();
	// 	log("ioctlsocket() failed: " + std::to_string(getLastSocketError()));
	// }

	if (length == SOCKET_ERROR) {
		if (error == WSAEWOULDBLOCK) {
			return {};
		}

		log("recv() failed: " + error);
		gracefullyCloseRemoteSocket();
		sendRst();
		setTcpStatus(TcpStatus::CLOSED);

		return {};
	}

	if (length == 0) {
		// Connection closed
		gracefullyCloseRemoteSocket();
		if (
			tcpStatus == TcpStatus::FIN_WAIT_1
			|| tcpStatus == TcpStatus::FIN_WAIT_2 || tcpStatus == TcpStatus::CLOSE_WAIT || shouldSendFinOnAckedEverything
		) {
			return {};
		}

		if (unAckedBytes > 0) {
			log("Waiting for ack on everything before closing connection");
			shouldSendFinOnAckedEverything = true;
		} else {
			log("We are initiating TCP close");
			sendFinAck();
			setTcpStatus(TcpStatus::FIN_WAIT_1);
			finSequenceNumber = ourSequenceNumber.load();
			ourSequenceNumber += 1;
		}

		return {};
	}

	{
		auto writeLock = getWriteLock();
		// dataStream.reserve(dataStream.size() + length);
		// dataStream.emplace_back(buffer.begin(), buffer.begin() + length);
		if (dataStream.size() < 1'000'000) {
			dataStream.insert(dataStream.end(), buffer.begin(), buffer.begin() + length);
		}
	}
	receivedBytes += length;

	return {buffer.begin(), buffer.begin() + length};
}

void TcpConnection::writeEvent() {
	if (this->remoteSocketStatus == RemoteSocketStatus::INITIATING) {
		setRemoteSocketStatus(RemoteSocketStatus::ESTABLISHED);
		u_long mode = 0;// Blocking mode
		ioctlSocket(socket, FIONBIO, &mode);
		sendSynAck();
		ourSequenceNumber += 1;
	}
}

void TcpConnection::exceptionEvent() {
	if (this->remoteSocketStatus == RemoteSocketStatus::INITIATING) {
		u_long mode = 0;// Blocking mode
		ioctlSocket(socket, FIONBIO, &mode);
		sendRst();
		gracefullyCloseRemoteSocket();
		setTcpStatus(TcpStatus::CLOSED);
	}
}

std::unique_ptr<pcpp::Packet> TcpConnection::encapsulateResponseDataToPacket(std::span<const uint8_t> data) {
	pcpp::Layer *ipLayer = buildIpLayer().release();

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

void TcpConnection::sendDataToDeviceSocket(std::span<const uint8_t> data) {
	ZoneScoped;
	size_t offset = 0;
	unsigned int maxSegmentSize = this->maxSegmentSize < DEFAULT_MAX_SEGMENT_SIZE ? this->maxSegmentSize : DEFAULT_MAX_SEGMENT_SIZE;
	while (offset < data.size()) {
		const unsigned int length = std::min(offset + maxSegmentSize, data.size()) - offset;
		const bool isLast = offset + length == data.size();
		const auto packet = encapsulateResponseDataToPacket(std::span(data.begin() + offset, data.begin() + offset + length));
		if (!packet) {
			break;
		}
		if (isLast) {
			packet->getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->pshFlag = 1;
		}

		// log(
		// 	"Sending to: " + originHostIp.toString() + ":" + std::to_string(originHostPort) + " " + PacketUtils::toString(*packet)
		// );

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
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->rstFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDeviceSocket(packet);
}

// unsigned long TcpConnection::getBytesAvailable(SOCKET socket) {
// 	unsigned long bytes;
// 	ioctlsocket(socket,FIONREAD, &bytes);
//
// 	return bytes;
// }

TcpStatus TcpConnection::getTcpStatus() const {
	return tcpStatus.load();
}

void TcpConnection::setTcpStatus(TcpStatus tcpStatus) {
	if (this->tcpStatus != tcpStatus) {
		log("TCP status changed from " + tcpStatusToString(this->tcpStatus) + " to " + tcpStatusToString(tcpStatus));
	}
	this->tcpStatus = tcpStatus;
}

void TcpConnection::forcefullyCloseAll() {
	if (this->remoteSocketStatus != RemoteSocketStatus::CLOSED) {
		closeSocketAndInvalidate();
		setRemoteSocketStatus(RemoteSocketStatus::CLOSED);
	}
	if (this->tcpStatus != TcpStatus::CLOSED) {
		sendRst();
	}
	setTcpStatus(TcpStatus::CLOSED);
}
