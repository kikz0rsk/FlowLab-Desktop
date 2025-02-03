#include "proxy_service.h"

#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <winsock2.h>
#include <iostream>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/SystemUtils.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>

#include "logger.h"
#include "packet_utils.h"
#include "socket_utils.h"
#include "tcp_connection.h"
#include "udp_connection.h"

ProxyService::ProxyService() {
	WSADATA wsaData;

	int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (res != 0) {
		Logger::get().log("WSAStartup failed: " + std::to_string(res));
		WSACleanup();

		exit(-1);
	}

	dnsManager = std::make_shared<DnsManager>();
	connections = std::make_shared<ConnectionManager>();
	ndpiStruct = ndpi::ndpi_init_detection_module(nullptr);
	if (ndpiStruct == nullptr) {
		throw std::runtime_error("Failed to initialize nDPI");
	}
	ndpi::ndpi_protocol_bitmask_struct_t all;
	NDPI_BITMASK_SET_ALL(all);
	ndpi::ndpi_set_protocol_detection_bitmask2(ndpiStruct, &all);
	ndpi::ndpi_finalize_initialization(ndpiStruct);
}

ProxyService::~ProxyService() {
	stop();
	WSACleanup();
	ndpi::ndpi_exit_detection_module(ndpiStruct);
}

void ProxyService::start() {
	stopFlag = false;
	pcapWriter = std::make_shared<pcpp::PcapFileWriterDevice>("output.pcapng", pcpp::LINKTYPE_IPV4);
	if (!pcapWriter->open()){
		std::cerr << "Cannot open output.pcap for writing" << std::endl;
		exit(210);
	}

	thread = std::thread(
		[this] {
			threadRoutine();
		}
	);
}

void ProxyService::stop() {
	stopFlag = true;
	closesocket(serverSocket);
	if (thread.joinable()) {
		thread.join();
	}
	for (auto& conn : connections->getConnections()) {
		if (conn.second->getRemoteSocketStatus() == RemoteSocketStatus::CLOSED) {
			continue;
		}
		conn.second->closeRemoteSocket();
	}
}

void ProxyService::threadRoutine() {
	serverSocket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serverSocket == INVALID_SOCKET) {
		std::cerr << "socket() failed: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	serverSocket6 = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (serverSocket6 == INVALID_SOCKET) {
		std::cerr << "socket() ipv6 failed: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	auto addr = sockaddr_in{AF_INET, htons(20'000), INADDR_ANY};
	int res = bind(serverSocket, (SOCKADDR *) &addr, sizeof(sockaddr_in));
	if (res == SOCKET_ERROR) {
		std::cerr << "bind() failed: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	auto addr6 = ndpi::sockaddr_in6{AF_INET6, htons(20'000), INADDR_ANY};
	res = bind(serverSocket6, (SOCKADDR *) &addr6, sizeof(ndpi::sockaddr_in6));
	if (res == SOCKET_ERROR) {
		std::cerr << "bind() ipv6 failed: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	u_long mode = 1;	// Non-blocking mode
	res = ioctlsocket(serverSocket, FIONBIO, &mode);
	if (res == SOCKET_ERROR) {
		std::cerr << "failed to set socket to non-blocking: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	res = ioctlsocket(serverSocket6, FIONBIO, &mode);
	if (res == SOCKET_ERROR) {
		std::cerr << "failed to set ipv6 socket to non-blocking: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	res = listen(serverSocket, 1);
	if (res == SOCKET_ERROR) {
		std::cerr << "listen() failed: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	res = listen(serverSocket6, 1);
	if (res == SOCKET_ERROR) {
		std::cerr << "listen() ipv6 failed: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	// setStatusBarMessage("Socket ready on port " + std::to_string(ntohs(addr.sin_port)));

	while (!stopFlag.load()) {
		try {
			while (!stopFlag.load()) {
				acceptClient4();
				acceptClient6();
				packetLoop();
			}
		} catch (const std::exception &e) {}

		// setStatusBarMessage("Device disconnected");
	}
}

void ProxyService::acceptClient4() {
	sockaddr_storage addrStorage{};
	int addrSize = sizeof(addrStorage);
	SOCKET clientSocket = accept(this->serverSocket, (sockaddr *)&addrStorage, &addrSize);
	if (clientSocket == INVALID_SOCKET) {
		const auto errCode = WSAGetLastError();
		if (errCode == WSAEWOULDBLOCK || errCode == WSAEINPROGRESS) {
			return;
		}
		Logger::get().log("accept() failed: " + std::to_string(WSAGetLastError()));

		return;
	}

	pcpp::IPAddress clientIp;
	uint16_t port;
	if (((sockaddr *)&addrStorage)->sa_family == AF_INET) {
		auto addr = reinterpret_cast<sockaddr_in *>(&addrStorage);
		clientIp = pcpp::IPAddress(std::string(inet_ntoa(addr->sin_addr)));
		port = ntohs(addr->sin_port);
	} else {
		auto addr = reinterpret_cast<ndpi::sockaddr_in6 *>(&addrStorage);
		std::array<char, INET6_ADDRSTRLEN> buffer{};
		ndpi::inet_ntop(AF_INET6, &addr->sin6_addr, buffer.data(), sizeof(buffer));
		clientIp = pcpp::IPAddress(std::string(buffer.data()));
		port = ntohs(addr->sin6_port);
	}

	this->clients.emplace_back(std::make_shared<Client>(clientSocket, clientIp, port));
	Logger::get().log("Accepted client from " + clientIp.toString());
}

void ProxyService::acceptClient6() {
	sockaddr_storage addrStorage{};
	int addrSize = sizeof(addrStorage);
	SOCKET clientSocket = accept(this->serverSocket6, (sockaddr *)&addrStorage, &addrSize);
	if (clientSocket == INVALID_SOCKET) {
		const auto errCode = WSAGetLastError();
		if (errCode == WSAEWOULDBLOCK || errCode == WSAEINPROGRESS) {
			return;
		}
		Logger::get().log("accept() failed: " + std::to_string(WSAGetLastError()));

		return;
	}

	pcpp::IPAddress clientIp;
	uint16_t port;
	if (((sockaddr *)&addrStorage)->sa_family == AF_INET) {
		auto addr = reinterpret_cast<sockaddr_in *>(&addrStorage);
		clientIp = pcpp::IPAddress(std::string(inet_ntoa(addr->sin_addr)));
		port = ntohs(addr->sin_port);
	} else {
		auto addr = reinterpret_cast<ndpi::sockaddr_in6 *>(&addrStorage);
		std::array<char, INET6_ADDRSTRLEN> buffer{};
		ndpi::inet_ntop(AF_INET6, &addr->sin6_addr, buffer.data(), sizeof(buffer));
		clientIp = pcpp::IPAddress(std::string(buffer.data()));
		port = ntohs(addr->sin6_port);
	}

	this->clients.emplace_back(std::make_shared<Client>(clientSocket, clientIp, port));
	Logger::get().log("Accepted client from " + clientIp.toString());
}

void ProxyService::packetLoop() {
	// setStatusBarMessage("Device connected");
	fd_set readFds;
	fd_set writeFds;
	fd_set exceptionFds;
	FD_ZERO(&readFds);
	FD_ZERO(&writeFds);
	FD_ZERO(&exceptionFds);
	for (const auto& client : clients) {
		FD_SET(client->getClientSocket(), &readFds);
	}
	std::vector<std::shared_ptr<Connection>> connectionsInFd{};
	connectionsInFd.reserve(connections->getConnections().size());
	for (const auto &conn: connections->getConnections()) {
		if (conn.second->getProtocol() == Protocol::UDP && conn.second->getRemoteSocketStatus() == RemoteSocketStatus::CLOSED) {
			continue;
		}
		if (
			conn.second->getProtocol() == Protocol::TCP
			&& conn.second->getRemoteSocketStatus() == RemoteSocketStatus::CLOSED
			&& dynamic_cast<TcpConnection *>(conn.second.get()) != nullptr
			&& dynamic_cast<TcpConnection *>(conn.second.get())->getTcpStatus() == TcpStatus::CLOSED
		) {
			continue;
		}
		FD_SET(conn.second->getSocket(), &readFds);
		FD_SET(conn.second->getSocket(), &writeFds);
		FD_SET(conn.second->getSocket(), &exceptionFds);
		connectionsInFd.emplace_back(conn.second);
	}

	const TIMEVAL timeout{0, 10'000};
	select(0, &readFds, &writeFds, &exceptionFds, &timeout);

	// if (FD_ISSET(this->clientSocket, &exceptionFds)) {
	// 	Logger::get().log("Exception on socket: " + std::to_string(WSAGetLastError()));
	// 	break;
	// }

	for (auto it = this->clients.begin(); it != this->clients.end();) {
		const auto& client = *it;
		if (FD_ISSET(client->getClientSocket(), &readFds)) {
			try {
				sendFromDevice(client);
			} catch (const SocketUtils::EofException &e) {
				Logger::get().log("Client closed connection");
				cleanUpAfterClient(client);
				it = clients.erase(it);
				continue;
			} catch (const SocketUtils::SocketError &e) {
				Logger::get().log("Socket error: " + std::string(e.what()));
				cleanUpAfterClient(client);
				it = clients.erase(it);
				continue;
			}
		}
		++it;
	}

	for (auto &conn: connectionsInFd) {
		if (FD_ISSET(conn->getSocket(), &readFds)) {
			const auto data = conn->read();
			if (data.empty()) {
				continue;
			}

			conn->sendDataToDeviceSocket(data);
		}
		if (FD_ISSET(conn->getSocket(), &writeFds)) {
			conn->writeEvent();
			Logger::get().log("Write event");
		}
		if (FD_ISSET(conn->getSocket(), &exceptionFds)) {
			conn->exceptionEvent();
		}
	}
}

void ProxyService::sendFromDevice(std::shared_ptr<Client> client) {
	std::array<char, 65535> buffer{};

	bool isIpv6 = false;
	int totalLength{};

	SocketUtils::readExactly(client->getClientSocket(), buffer.data(), 1);
	if ((buffer[0] >> 4) & 0xF == 6) {
		isIpv6 = true;
	}

	if (isIpv6) {
		SocketUtils::readExactly(client->getClientSocket(), buffer.data() + 1, 5);
		const auto payloadLength = static_cast<uint8_t>(buffer[4]) << 8 | static_cast<uint8_t>(buffer[5]);
		totalLength = payloadLength + 40;
		SocketUtils::readExactly(client->getClientSocket(), buffer.data() + 6, totalLength - 6);
	} else {
		SocketUtils::readExactly(client->getClientSocket(), buffer.data() + 1, 3);
		totalLength = static_cast<uint8_t>(buffer[2]) << 8 | static_cast<uint8_t>(buffer[3]);
		// Logger::get().log("Received packet of length " + std::to_string(length));
		SocketUtils::readExactly(client->getClientSocket(), buffer.data() + 4, totalLength - 4);
	}

	try {

	} catch (const SocketUtils::EofException &e) {
		this->clients.remove(client);
		Logger::get().log("Client closed connection");

		return;
	} catch (const SocketUtils::SocketError &e) {
		this->clients.remove(client);
		Logger::get().log("Socket error: " + std::string(e.what()));

		return;
	}

	timeval time{};
	gettimeofday(&time, nullptr);
	pcpp::RawPacket packet(reinterpret_cast<const uint8_t *>(buffer.data()), totalLength, time, false, pcpp::LINKTYPE_IPV4);
	pcpp::Packet parsedPacket(&packet);
	// Logger::get().log("Received: " + PacketUtils::toString(parsedPacket));

	pcpp::IPAddress srcIp;
	pcpp::IPAddress dstIp;

	pcpp::Layer* networkLayer;
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

		return;
	}

	uint16_t srcPort{};
	uint16_t dstPort{};
	Protocol protocol = Protocol::UDP;
	// Logger::get().log("Received: " + PacketUtils::toString(parsedPacket));

	pcapWriter->writePacket(*parsedPacket.getRawPacketReadOnly());

	if (auto tcpPacket = parsedPacket.getLayerOfType<pcpp::TcpLayer>()) {
		srcPort = tcpPacket->getSrcPort();
		dstPort = tcpPacket->getDstPort();
		protocol = Protocol::TCP;
	} else if (auto udpPacket = parsedPacket.getLayerOfType<pcpp::UdpLayer>()) {
		srcPort = udpPacket->getSrcPort();
		dstPort = udpPacket->getDstPort();
		protocol = Protocol::UDP;
	} else {
		Logger::get().log("Ignoring this unsupported packet");

		return;
	}

	if (const auto dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>()) {
		dnsManager->processDns(*dnsLayer);
	}

	auto connection = connections->find(client->getClientIp(), srcIp, dstIp, srcPort, dstPort, protocol);
	bool newConnection = false;
	if (!connection) {
		if (protocol == Protocol::TCP) {
			if (auto tcpPacket = parsedPacket.getLayerOfType<pcpp::TcpLayer>()) {
				if (tcpPacket->getTcpHeader()->synFlag == 0) {
					Logger::get().log("Received non-SYN packet for non-existing connection, ignoring...");

					// Send RST

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
					tcpLayer->getTcpHeader()->sequenceNumber = tcpPacket->getTcpHeader()->ackNumber;
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
					pcapWriter->writePacket(rawPacket);

					send(
						client->getClientSocket(),
						reinterpret_cast<const char *>(rstPacket.getRawPacketReadOnly()->getRawData()),
						rstPacket.getRawPacketReadOnly()->getRawDataLen(),
						0
					);

					return;
				}
			}

			connection = std::make_shared<TcpConnection>(
				client,
				srcIp,
				dstIp,
				srcPort,
				dstPort,
				ndpiStruct
			);
		} else {
			connection = std::make_shared<UdpConnection>(
				client,
				srcIp,
				dstIp,
				srcPort,
				dstPort,
				ndpiStruct
			);
		}

		connection->setPcapWriter(pcapWriter);
		connection->setDnsManager(dnsManager);
		connections->addConnection(connection);
		newConnection = true;
	}

	if (newConnection) {
		// connectionsPage->addConnection(connection);
	}

	connection->processPacketFromDevice(networkLayer);
}

void ProxyService::cleanUpAfterClient(std::shared_ptr<Client> client) {
	for (const auto& conn : connections->getConnections()) {
		if (conn.second->getClient() == client) {
			conn.second->closeAll();
		}
	}
}
