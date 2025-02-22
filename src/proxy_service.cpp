#include "proxy_service.h"

#include <iostream>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/SystemUtils.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include "tracy/Tracy.hpp"

#include "logger.h"
#include "packet_utils.h"
#include "socket_utils.h"
#include "tcp_connection.h"
#include "udp_connection.h"

ProxyService::ProxyService() {
	int res = initSockets();
	if (res != 0) {
		Logger::get().log("Init sockets failed: " + std::to_string(res));

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
	cleanupSockets();
	ndpi::ndpi_exit_detection_module(ndpiStruct);
}

void ProxyService::start() {
	stopFlag = false;
	pcapWriter = std::make_shared<pcpp::PcapNgFileWriterDevice>("output.pcapng");
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
	closesocket(serverSocket6);
	if (thread.joinable()) {
		thread.join();
	}
	for (auto& conn : connections->getConnections()) {
		if (conn.second->getRemoteSocketStatus() == RemoteSocketStatus::CLOSED) {
			continue;
		}
		conn.second->gracefullyCloseRemoteSocket();
	}
}

void ProxyService::registerConnectionCallback(const OnConnectionCallback &callback) {
	onConnectionCallbacks.emplace(callback);
}

void ProxyService::unregisterConnectionCallback(OnConnectionCallback callback) {
	for (auto it = onConnectionCallbacks.begin(); it != onConnectionCallbacks.end(); ++it) {
		if (*it == callback) {
			onConnectionCallbacks.erase(it);
			break;
		}
	}
}

std::shared_ptr<ConnectionManager> ProxyService::getConnections() const {
	return connections;
}

std::shared_ptr<DnsManager> ProxyService::getDnsManager() const {
	return dnsManager;
}

std::shared_ptr<pcpp::PcapNgFileWriterDevice> ProxyService::getPcapWriter() const {
	return pcapWriter;
}

ndpi::ndpi_detection_module_struct * ProxyService::getNdpiStruct() const {
	return ndpiStruct;
}

void ProxyService::threadRoutine() {
	serverSocket6 = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (serverSocket6 == INVALID_SOCKET) {
		std::cerr << "socket() ipv6 failed: " << getLastSocketError() << std::endl;

		return;
	}

	const int opt = 0;
	setsockopt(serverSocket6, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&opt), sizeof(opt));

	sockaddr_in6 addr6{};
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(20'000);
	addr6.sin6_addr = in6addr_any;
	int res = bind(serverSocket6, (SOCKADDR *) &addr6, sizeof(addr6));
	if (res == SOCKET_ERROR) {
		std::cerr << "bind() ipv6 failed: " << getLastSocketError() << std::endl;

		return;
	}

	u_long mode = 1;	// Non-blocking mode
	res = ioctlsocket(serverSocket6, FIONBIO, &mode);
	if (res == SOCKET_ERROR) {
		std::cerr << "failed to set ipv6 socket to non-blocking: " << getLastSocketError() << std::endl;

		return;
	}

	res = listen(serverSocket6, 1);
	if (res == SOCKET_ERROR) {
		std::cerr << "listen() ipv6 failed: " << getLastSocketError() << std::endl;

		return;
	}

	// setStatusBarMessage("Socket ready on port " + std::to_string(ntohs(addr.sin_port)));

	while (!stopFlag.load()) {
		try {
			while (!stopFlag.load()) {
				selectLoop();
			}
		} catch (const std::exception &e) {}

		// setStatusBarMessage("Device disconnected");
	}
}

void ProxyService::acceptClient6() {
	ZoneScoped;
	sockaddr_storage addrStorage{};
	int addrSize = sizeof(addrStorage);
	SOCKET clientSocket = accept(this->serverSocket6, (sockaddr *)&addrStorage, &addrSize);
	if (clientSocket == INVALID_SOCKET) {
		const auto errCode = getLastSocketError();
		if (errCode == WSAEWOULDBLOCK || errCode == WSAEINPROGRESS) {
			return;
		}
		Logger::get().log("accept() failed: " + std::to_string(getLastSocketError()));

		return;
	}

	pcpp::IPAddress clientIp;
	uint16_t port;
	if (((sockaddr *)&addrStorage)->sa_family == AF_INET) {
		auto addr = reinterpret_cast<sockaddr_in *>(&addrStorage);
		clientIp = pcpp::IPAddress(std::string(inet_ntoa(addr->sin_addr)));
		port = ntohs(addr->sin_port);
	} else {
		auto addr = reinterpret_cast<sockaddr_in6 *>(&addrStorage);
		std::array<char, INET6_ADDRSTRLEN> buffer{};
		inet_ntop(AF_INET6, &addr->sin6_addr, buffer.data(), sizeof(buffer));
		clientIp = pcpp::IPAddress(std::string(buffer.data()));
		port = ntohs(addr->sin6_port);
	}

	auto& client = this->clients.emplace_back(std::make_shared<Client>(clientSocket, clientIp, port));
	std::shared_ptr<Botan::AutoSeeded_RNG> rng = std::make_shared<Botan::AutoSeeded_RNG>();
	std::shared_ptr<Botan::TLS::Session_Manager_In_Memory> session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
	std::shared_ptr<ServerCredentials> creds = std::make_shared<ServerCredentials>();
	std::shared_ptr<Botan::TLS::Strict_Policy> policy = std::make_shared<Botan::TLS::Strict_Policy>();
	std::shared_ptr<Botan::TLS::Callbacks> callbacks = std::make_shared<ServerCallbacks>(*client);
	auto server = std::make_shared<Botan::TLS::Server>(callbacks, session_mgr, creds, policy, rng);
	client->setTlsServer(server);
	Logger::get().log("Accepted client from " + clientIp.toString());
}

void ProxyService::selectLoop() {
	// setStatusBarMessage("Device connected");
	ZoneScoped;
	fd_set readFds;
	fd_set writeFds;
	fd_set exceptionFds;
	FD_ZERO(&readFds);
	FD_ZERO(&writeFds);
	FD_ZERO(&exceptionFds);

	FD_SET(serverSocket6, &readFds);
	for (const auto& client : clients) {
		FD_SET(client->getClientSocket(), &readFds);
		FD_SET(client->getClientSocket(), &writeFds);
	}
	std::vector<std::shared_ptr<Connection>> connectionsInFd{};
	connectionsInFd.reserve(connections->getConnections().size());
	for (const auto &conn: connections->getConnections()) {
		if (conn.second->getRemoteSocketStatus() == RemoteSocketStatus::CLOSED) {
			continue;
		}

		FD_SET(conn.second->getSocket(), &readFds);
		FD_SET(conn.second->getSocket(), &writeFds);
		FD_SET(conn.second->getSocket(), &exceptionFds);
		connectionsInFd.emplace_back(conn.second);
	}

	constexpr TIMEVAL timeout{0, 100'000};
	select(0, &readFds, &writeFds, &exceptionFds, &timeout);

	if (FD_ISSET(serverSocket6, &readFds)) {
		acceptClient6();
	}

	for (auto it = this->clients.begin(); it != this->clients.end();) {
		const auto& client = *it;
		try {
			if (FD_ISSET(client->getClientSocket(), &readFds)) {
				readTlsData(client);

				bool multiplePackets = false;
				do {
					multiplePackets = sendFromDevice(client);
				} while (multiplePackets);
			}
			if (FD_ISSET(client->getClientSocket(), &writeFds)) {
				if (!client->getUnencryptedQueueToDevice().empty()) {
					auto& data = client->getUnencryptedQueueToDevice().front();
					client->getTlsConnection()->send(data);
					data.clear();
				}
				if (!client->getEncryptedQueueToDevice().empty()) {
					auto& data = client->getEncryptedQueueToDevice();
					int res = SocketUtils::write(client->getClientSocket(), reinterpret_cast<char *>(data.data()), data.size());
					if (res != SOCKET_ERROR) {
						data.erase(data.begin(), data.begin() + res);
						Logger::get().log("Sent " + std::to_string(res) + " bytes to client");
					}
				}
				// try {
				// 	const auto& data = client->getUnencryptedQueueToDevice().front();
				// 	client->getTlsServer()->send(data);
				// 	SocketUtils::writeExactlyThrowBlock(client->getClientSocket(), reinterpret_cast<const char *>(data.data()), data.size());
				// 	client->getUnencryptedQueueToDevice().pop();
				// } catch (const SocketUtils::WouldBlockException& e) {
				//
				// }
			}
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
			// Logger::get().log("Write event");
		}
		if (FD_ISSET(conn->getSocket(), &exceptionFds)) {
			conn->exceptionEvent();
		}
	}
}

void ProxyService::readTlsData(std::shared_ptr<Client> client) {
	ZoneScoped;
	auto server = client->getTlsConnection();
	std::array<char, 65535> buffer{};
	const int bytesRead = SocketUtils::read(client->getClientSocket(), buffer.data(), buffer.size());
	if (bytesRead == SOCKET_ERROR) {
		const int error = getLastSocketError();
		if (error == WSAEWOULDBLOCK) {
			return;
		}
		throw SocketUtils::SocketError(error);
	}
	Logger::get().log("Received " + std::to_string(bytesRead) + " TLS bytes from client");
	server->received_data(std::span(reinterpret_cast<uint8_t*>(buffer.data()), bytesRead));
}

bool ProxyService::sendFromDevice(std::shared_ptr<Client> client) {
	ZoneScoped;
	if (client->getUnencryptedQueueFromDevice().empty()) {
		return false;
	}

	// std::array<char, 65535> buffer{};
	auto& buffer = client->getUnencryptedQueueFromDevice();
	if (buffer.size() < 20) {
		return false;
	}

	bool isIpv6 = false;
	int totalLength{};

	// SocketUtils::readExactly(client->getClientSocket(), buffer.data(), 1);
	if (((buffer[0] >> 4) & 0xF) == 6) {
		isIpv6 = true;
	}

	if (isIpv6) {
		// SocketUtils::readExactly(client->getClientSocket(), buffer.data() + 1, 5);
		const auto payloadLength = (buffer[4] << 8) | (buffer[5]);
		totalLength = payloadLength + 40;
		// SocketUtils::readExactly(client->getClientSocket(), buffer.data() + 6, totalLength - 6);
	} else {
		// SocketUtils::readExactly(client->getClientSocket(), buffer.data() + 1, 3);
		totalLength = (buffer[2] << 8) | (buffer[3]);
		// Logger::get().log("Received packet of length " + std::to_string(length));
		// SocketUtils::readExactly(client->getClientSocket(), buffer.data() + 4, totalLength - 4);
	}

	if (buffer.size() < totalLength) {
		// we don't have the full packet yet
		return false;
	}

	std::vector packetBuffer(buffer.begin(), buffer.begin() + totalLength);
	buffer.erase(buffer.begin(), buffer.begin() + totalLength);

	timeval time{};
	gettimeofday(&time, nullptr);
	pcpp::RawPacket packet(packetBuffer.data(), totalLength, time, false, isIpv6 ? pcpp::LINKTYPE_IPV6 : pcpp::LINKTYPE_IPV4);
	pcpp::Packet parsedPacket(&packet);
	// Logger::get().log("Received: " + PacketUtils::toString(parsedPacket));

	pcpp::IPAddress srcIp;
	pcpp::IPAddress dstIp;

	pcapWriter->writePacket(*parsedPacket.getRawPacketReadOnly());
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

		return true;
	}

	uint16_t srcPort{};
	uint16_t dstPort{};
	Protocol protocol = Protocol::UDP;
	// Logger::get().log("Received: " + PacketUtils::toString(parsedPacket));

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

					client->getTlsConnection()->send(rstPacket.getRawPacketReadOnly()->getRawData(), rstPacket.getRawPacketReadOnly()->getRawDataLen());
					// client->getUnencryptedQueueToDevice().emplace(
					// 	rstPacket.getRawPacketReadOnly()->getRawData(),
					// 	rstPacket.getRawPacketReadOnly()->getRawData() + rstPacket.getRawPacketReadOnly()->getRawDataLen()
					// );
					// send(
					// 	client->getClientSocket(),
					// 	reinterpret_cast<const char *>(rstPacket.getRawPacketReadOnly()->getRawData()),
					// 	rstPacket.getRawPacketReadOnly()->getRawDataLen(),
					// 	0
					// );

					return true;
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
		for (const auto& callback : onConnectionCallbacks) {
			callback->operator()(true, connection);
		}
	}

	connection->processPacketFromDevice(networkLayer);

	return true;
}

void ProxyService::cleanUpAfterClient(std::shared_ptr<Client> client) {
	for (const auto& conn : connections->getConnections()) {
		if (conn.second->getClient() == client) {
			conn.second->forcefullyCloseAll();
		}
	}
}
