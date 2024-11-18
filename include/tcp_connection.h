#pragma once

#include <random>

#include "connection.h"

#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/SystemUtils.h>

class TcpConnection : public Connection {
	protected:
		unsigned int ackNumber{};
		std::atomic_uint32_t ourSequenceNumber = 0;
		unsigned short windowSize = 32767;
		SOCKET deviceSocket;
		std::thread connectingThread;

	public:
		TcpConnection(
			pcpp::IPAddress originHostIp,
			uint16_t originHostPort,
			const pcpp::IPAddress &src_ip,
			const pcpp::IPAddress &dst_ip,
			uint16_t src_port,
			uint16_t dst_port,
			SOCKET deviceSocket
		)	:
			Connection(originHostIp, originHostPort, src_ip, dst_ip, src_port, dst_port, Protocol::TCP), deviceSocket(deviceSocket) {}
		~TcpConnection() override {
			close();
			if (connectingThread.joinable()) {
				connectingThread.join();
			}
		}

		void close() {
			remoteSocketStatus = RemoteSocketStatus::CLOSED;
			closesocket(socket);
		}

		void sendFinAck() {
			auto ipLayer = new pcpp::IPv4Layer(dstIp.getIPv4(), srcIp.getIPv4());
			ipLayer->getIPv4Header()->timeToLive = 64;
			ipLayer->getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;

			auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
			tcpLayer->getTcpHeader()->finFlag = 1;
			tcpLayer->getTcpHeader()->ackFlag = 1;
			tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
			tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
			tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(windowSize);

			pcpp::Packet packet(50);
			packet.addLayer(ipLayer, true);
			packet.addLayer(tcpLayer, true);

			packet.computeCalculateFields();

			Logger::get().log("Sending: " + PacketUtils::toString(packet));

			sendto(
				deviceSocket,
				reinterpret_cast<const char *>(packet.getRawPacketReadOnly()->getRawData()),
				packet.getRawPacketReadOnly()->getRawDataLen(),
				0,
				(SOCKADDR *) &originSockAddr,
				sizeof(originSockAddr)
			);
		}

		void sendSynAck() {
			auto ipLayer = new pcpp::IPv4Layer(dstIp.getIPv4(), srcIp.getIPv4());
			ipLayer->getIPv4Header()->timeToLive = 64;
			ipLayer->getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;

			auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
			tcpLayer->getTcpHeader()->synFlag = 1;
			tcpLayer->getTcpHeader()->ackFlag = 1;
			tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
			tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
			tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(windowSize);

			pcpp::Packet packet(50);
			packet.addLayer(ipLayer, true);
			packet.addLayer(tcpLayer, true);

			packet.computeCalculateFields();

			Logger::get().log("Sending: " + PacketUtils::toString(packet));

			sendto(
				deviceSocket,
				reinterpret_cast<const char *>(packet.getRawPacketReadOnly()->getRawData()),
				packet.getRawPacketReadOnly()->getRawDataLen(),
				0,
				(SOCKADDR *) &originSockAddr,
				sizeof(originSockAddr)
			);
		}

		void processPacketFromDevice(pcpp::IPv4Layer *ipv4Layer) override {
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

			if (tcpLayer->getTcpHeader()->synFlag == 1 && tcpStatus != TcpStatus::SYN_RECEIVED) {
				ackNumber = packetSequenceNumber + 1;
				std::random_device rd;
				std::mt19937 gen(rd());
				std::uniform_int_distribution<std::mt19937::result_type> distrib(1, std::numeric_limits<uint32_t>::max());
				ourSequenceNumber = distrib(gen);
				tcpStatus = TcpStatus::SYN_RECEIVED;
				openSocket();

				return;
			}

			if (packetSequenceNumber != ackNumber) {
				Logger::get().log(
					"Received unexpected packet, this packet seq="
					+ std::to_string(packetSequenceNumber)
					+ ", expected="
					+ std::to_string(ackNumber)
				);
				sendAck();

				return;
			}

			unsigned int dataSize = tcpLayer->getLayerPayloadSize();
			if (dataSize > 0) {
				auto data = tcpLayer->getLayerPayload();
				{
					auto writeLock = getWriteLock();
					dataStream.reserve(dataStream.size() + dataSize);
					dataStream.insert(dataStream.end(), data, data + dataSize);
				}

				sendDataToRemote(std::vector(tcpLayer->getLayerPayload(), tcpLayer->getLayerPayload() + tcpLayer->getLayerPayloadSize()));
			}

			// TODO add check for expected sequence

			ackNumber = packetSequenceNumber;
			if (dataSize > 0) {
				ackNumber += dataSize;
				sendAck();
			}

			if (tcpLayer->getTcpHeader()->rstFlag == 1) {
				remoteSocketStatus = RemoteSocketStatus::CLOSED;
				close();

				return;
			}

			if (tcpLayer->getTcpHeader()->finFlag == 1) {
				if (tcpStatus == TcpStatus::FIN_SENT) {
					remoteSocketStatus = RemoteSocketStatus::CLOSED;
					ourSequenceNumber += 1;
					ackNumber += 1;
					sendAck();
					close();

					return;
				} else {
					ackNumber += 1;
					sendFinAck();
					ourSequenceNumber += 1;
					close();

					return;
				}
			}

			if (tcpLayer->getTcpHeader()->ackFlag == 1) {
				if (remoteSocketStatus == RemoteSocketStatus::INITIATING) {
					remoteSocketStatus = RemoteSocketStatus::ESTABLISHED;
				} else if (tcpStatus == TcpStatus::FIN_SENT) {
					remoteSocketStatus = RemoteSocketStatus::CLOSED;
					close();
				}
			}
		}

		void openSocket() {
			if (remoteSocketStatus == RemoteSocketStatus::ESTABLISHED) {
				close();
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
			auto dstIpStr = dstIp.toString();
			auto destSockAddr = sockaddr_in{AF_INET, htons(dstPort)};
			destSockAddr.sin_addr.s_addr = inet_addr(dstIpStr.c_str());
			remoteSocketStatus = RemoteSocketStatus::INITIATING;
			connectingThread = std::thread(
				[this, destSockAddr] {
					auto writeLock = getWriteLock();
					int res = connect(socket, (SOCKADDR *) &destSockAddr, sizeof(destSockAddr));
					if (res == SOCKET_ERROR) {
						std::cerr << "connect() failed: " << WSAGetLastError() << std::endl;
						remoteSocketStatus = RemoteSocketStatus::CLOSED;

						return;
					}

					remoteSocketStatus = RemoteSocketStatus::ESTABLISHED;
					sendSynAck();
					ourSequenceNumber += 1;
				}
			);
		}

		void sendAck() {
			auto ipLayer = new pcpp::IPv4Layer(dstIp.getIPv4(), srcIp.getIPv4());
			ipLayer->getIPv4Header()->timeToLive = 64;
			ipLayer->getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;

			auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
			tcpLayer->getTcpHeader()->ackFlag = 1;
			tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
			tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
			tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(windowSize);

			pcpp::Packet packet(50);
			packet.addLayer(ipLayer, true);
			packet.addLayer(tcpLayer, true);

			packet.computeCalculateFields();

			Logger::get().log("Sending: " + PacketUtils::toString(packet));

			sendto(
				deviceSocket,
				reinterpret_cast<const char *>(packet.getRawPacketReadOnly()->getRawData()),
				packet.getRawPacketReadOnly()->getRawDataLen(),
				0,
				(SOCKADDR *) &originSockAddr,
				sizeof(originSockAddr)
			);
		}

		void sendDataToRemote(const std::vector<uint8_t> &data) override {
			send(socket, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0);
		}

		std::vector<uint8_t> read() override {
			if (remoteSocketStatus != RemoteSocketStatus::ESTABLISHED) {
				return {};
			}

			std::array<char, 65535> buffer{};

			u_long mode = 1;// Non-blocking mode
			ioctlsocket(socket, FIONBIO, &mode);
			const int length = recv(socket, buffer.data(), buffer.size(), 0);

			mode = 0;	// Blocking mode
			ioctlsocket(socket, FIONBIO, &mode);

			if (length == 0) {
				// Connection closed
				if (tcpStatus == TcpStatus::FIN_SENT) {
					return {};
				}
				sendFinAck();
				tcpStatus = TcpStatus::FIN_SENT;

				return {};
			}

			if (length == SOCKET_ERROR) {
				const int error = WSAGetLastError();
				if (error == WSAEWOULDBLOCK) {
					return {};
				}

				Logger::get().log("recv() failed: " + error);
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

		std::unique_ptr<pcpp::Packet> encapsulateResponseDataToPacket(const std::vector<uint8_t> &data) override {
			auto ipLayer = new pcpp::IPv4Layer(dstIp.getIPv4(), srcIp.getIPv4());
			ipLayer->getIPv4Header()->timeToLive = 64;
			ipLayer->getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;

			auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
			tcpLayer->getTcpHeader()->ackFlag = 1;
			tcpLayer->getTcpHeader()->pshFlag = 1;
			tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
			tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
			tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(windowSize);
			auto payloadLayer = new pcpp::PayloadLayer(data.data(), data.size());

			auto udpPacket = std::make_unique<pcpp::Packet>(65'535);
			udpPacket->addLayer(ipLayer, true);
			udpPacket->addLayer(tcpLayer, true);
			udpPacket->addLayer(payloadLayer, true);

			udpPacket->computeCalculateFields();

			return udpPacket;
		}

		[[nodiscard]] std::atomic_uint32_t &getOurSequenceNumber() {
			return ourSequenceNumber;
		}
};
