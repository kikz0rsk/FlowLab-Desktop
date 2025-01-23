#include <QDebug>
#include <array>
#include <iostream>
#include <winsock2.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/SystemUtils.h>

#include "mainwindow.h"

#include "connections_page.h"
#include "./ui_mainwindow.h"
#include "logger.h"
#include "logswindow.h"
#include "dnspage.h"
#include "packet_utils.h"
#include "tcp_connection.h"
#include "udp_connection.h"
#include "syntax_highlighter.h"

MainWindow::MainWindow(QWidget *parent)	:
	QMainWindow(parent), ui(new Ui::MainWindow) {
	ui->setupUi(this);

	connectionsPage = new ConnectionsPage(*this);
	dnsPage = new DnsPage(*this, dnsManager);

	ui->tabWidget->addTab(connectionsPage, "Connections");
	ui->tabWidget->addTab(dnsPage, "DNS");

	connect(ui->actionShow_logs, &QAction::triggered, this, &MainWindow::actionShow_logs_clicked);
	connect(this, &MainWindow::setStatusBarMessage, this, &MainWindow::_setStatusBarMessage);

	ndpiStruct = ndpi::ndpi_init_detection_module(nullptr);
	if (ndpiStruct == nullptr) {
		throw std::runtime_error("Failed to initialize nDPI");
	}

	pcapWriter = std::make_shared<pcpp::PcapFileWriterDevice>("output.pcapng", pcpp::LINKTYPE_IPV4);
	if (!pcapWriter->open()){
		std::cerr << "Cannot open output.pcap for writing" << std::endl;
		exit(210);
	}

	ndpi::ndpi_protocol_bitmask_struct_t all;
	NDPI_BITMASK_SET_ALL(all);
	ndpi::ndpi_set_protocol_detection_bitmask2(ndpiStruct, &all);
	ndpi::ndpi_finalize_initialization(ndpiStruct);

	thread = std::thread(
		[this] {
			threadRoutine();
		}
	);
}

MainWindow::~MainWindow() {
	stopFlag = true;
	closesocket(serverSocket);
	thread.join();
	ndpi::ndpi_exit_detection_module(ndpiStruct);
	delete ui;
	WSACleanup();
}

void MainWindow::threadRoutine() {
	WSADATA wsaData;

	int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (res != 0) {
		printf("WSAStartup failed: %d\n", res);
		WSACleanup();

		return;
	}

	serverSocket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serverSocket == INVALID_SOCKET) {
		std::cerr << "socket() failed: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	auto addr = sockaddr_in{AF_INET, htons(20'000), INADDR_ANY};
	res = bind(serverSocket, (SOCKADDR *) &addr, sizeof(sockaddr_in));
	if (res == SOCKET_ERROR) {
		std::cerr << "bind() failed: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	res = listen(serverSocket, 1);
	if (res == SOCKET_ERROR) {
		std::cerr << "listen() failed: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	setStatusBarMessage("Socket ready on port " + std::to_string(ntohs(addr.sin_port)));

	while (!stopFlag.load()) {
		try {
			packetLoop();
		} catch (const std::exception &e) {}

		setStatusBarMessage("Device disconnected");
	}
}

std::string MainWindow::getKey(const pcpp::IPAddress &src_ip, const pcpp::IPAddress &dst_ip, uint16_t src_port, uint16_t dst_port, Protocol protocol) {
	return src_ip.toString() + "," + std::to_string(src_port) + "," + dst_ip.toString() + "," + std::to_string(dst_port) + "," + (protocol == Protocol::TCP ? "tcp" : "udp");
}

void MainWindow::packetLoop() {
	this->clientSocket = accept(this->serverSocket, nullptr, nullptr);
	if (this->clientSocket == INVALID_SOCKET) {
		Logger::get().log("accept() failed: " + std::to_string(WSAGetLastError()));

		return;
	}
	setStatusBarMessage("Device connected");
	while (!stopFlag.load()) {
		fd_set readFds;
		fd_set writeFds;
		fd_set exceptionFds;
		FD_ZERO(&readFds);
		FD_ZERO(&writeFds);
		FD_ZERO(&exceptionFds);
		FD_SET(this->clientSocket, &readFds);
		FD_SET(this->clientSocket, &exceptionFds);
		for (const auto &conn: connections.getConnections()) {
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
		}

		const TIMEVAL timeout{0, 500'000};
		select(0, &readFds, &writeFds, &exceptionFds, &timeout);

		if (FD_ISSET(this->clientSocket, &exceptionFds)) {
			Logger::get().log("Exception on socket: " + std::to_string(WSAGetLastError()));
			break;
		}

		if (FD_ISSET(this->clientSocket, &readFds)) {
			sendFromDevice();
			Logger::get().log({});
		}

		for (auto &conn: connections.getConnections()) {
			if (FD_ISSET(conn.second->getSocket(), &readFds)) {
				const auto data = conn.second->read();
				if (data.empty()) {
					continue;
				}

				Logger::get().log("Read " + std::to_string(data.size()) + " bytes from socket");

				conn.second->sendDataToDeviceSocket(data);
				Logger::get().log({});
			}
			if (FD_ISSET(conn.second->getSocket(), &writeFds)) {
				conn.second->writeEvent();
			}
			if (FD_ISSET(conn.second->getSocket(), &exceptionFds)) {
				conn.second->exceptionEvent();
			}
		}
	}
}

void MainWindow::sendFromDevice() {
	std::array<char, 65535> buffer{};

	sockaddr_in from{};
	readExactly(clientSocket, buffer.data(), 4);
	const auto length = static_cast<uint8_t>(buffer[2]) << 8 | static_cast<uint8_t>(buffer[3]);
	Logger::get().log("Received packet of length " + std::to_string(length));
	readExactly(clientSocket, buffer.data() + 4, length - 4);

	timeval time{};
	gettimeofday(&time, nullptr);
	pcpp::RawPacket packet(reinterpret_cast<const uint8_t *>(buffer.data()), length, time, false, pcpp::LINKTYPE_IPV4);
	pcpp::Packet parsedPacket(&packet);
	const auto ipv4Layer = dynamic_cast<pcpp::IPv4Layer *>(parsedPacket.getFirstLayer());
	if (ipv4Layer == nullptr) {
		Logger::get().log("Received packet is not IPv4");

		return;
	}

	uint16_t srcPort{};
	uint16_t dstPort{};
	Protocol protocol = Protocol::UDP;
	Logger::get().log("Received: " + PacketUtils::toString(parsedPacket));

	pcapWriter->writePacket(*parsedPacket.getRawPacketReadOnly());

	if (auto tcpPacket = dynamic_cast<pcpp::TcpLayer *>(ipv4Layer->getNextLayer())) {
		srcPort = tcpPacket->getSrcPort();
		dstPort = tcpPacket->getDstPort();
		protocol = Protocol::TCP;
	} else if (auto udpPacket = dynamic_cast<pcpp::UdpLayer *>(ipv4Layer->getNextLayer())) {
		srcPort = udpPacket->getSrcPort();
		dstPort = udpPacket->getDstPort();
		protocol = Protocol::UDP;
	} else {
		Logger::get().log("Ignoring this unsupported packet");

		return;
	}

	const auto dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();
	if (dnsLayer) {
		dnsManager.processDns(*dnsLayer);
	}

	auto connection = connections.find(ipv4Layer->getSrcIPAddress(), ipv4Layer->getDstIPAddress(), srcPort, dstPort, protocol);
	bool newConnection = false;
	if (!connection) {
		if (protocol == Protocol::TCP) {
			if (auto tcpPacket = dynamic_cast<pcpp::TcpLayer *>(ipv4Layer->getNextLayer())) {
				if (tcpPacket->getTcpHeader()->synFlag == 0) {
					Logger::get().log("Received non-SYN packet for non-existing connection, ignoring...");

					// Send RST
					auto ipLayer = new pcpp::IPv4Layer(ipv4Layer->getDstIPv4Address(), ipv4Layer->getSrcIPv4Address());
					ipLayer->getIPv4Header()->timeToLive = 64;
					ipLayer->getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;

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
						pcpp::LINKTYPE_IPV4
					);
					pcapWriter->writePacket(rawPacket);

					send(
						clientSocket,
						reinterpret_cast<const char *>(rstPacket.getRawPacketReadOnly()->getRawData()),
						rstPacket.getRawPacketReadOnly()->getRawDataLen(),
						0
					);

					return;
				}
			}

			connection = std::make_shared<TcpConnection>(
				pcpp::IPAddress(pcpp::IPv4Address((uint32_t) from.sin_addr.S_un.S_addr)),
				ntohs(from.sin_port),
				ipv4Layer->getSrcIPAddress(),
				ipv4Layer->getDstIPAddress(),
				srcPort,
				dstPort,
				clientSocket,
				ndpiStruct
			);
		} else {
			connection = std::make_shared<UdpConnection>(
				pcpp::IPAddress(pcpp::IPv4Address((uint32_t) from.sin_addr.S_un.S_addr)),
				ntohs(from.sin_port),
				ipv4Layer->getSrcIPAddress(),
				ipv4Layer->getDstIPAddress(),
				srcPort,
				dstPort,
				clientSocket,
				ndpiStruct
			);
		}

		connection->setPcapWriter(pcapWriter);
		connection->setDnsManager(&dnsManager);
		connections.addConnection(connection);
		newConnection = true;
	}

	if (newConnection) {
		connectionsPage->addConnection(connection);
		// auto *item = new QStandardItem(
		// 	QString::fromStdString(
		// 		connection->getSrcIp().toString()
		// 		+ ":" + std::to_string(connection->getSrcPort()) + " -> "
		// 		+ connection->getDstIp().toString() + ":" + std::to_string(connection->getDstPort())
		// 		+ " " + (connection->getProtocol() == Protocol::TCP ? "TCP" : "UDP")
		// 	)
		// );
		// item->setData(QVariant::fromValue(connection));
		// model.insertRow(0, item);
	}

	connection->processPacketFromDevice(ipv4Layer);
	Logger::get().log({});
}

void MainWindow::readExactly(SOCKET socket, char *buffer, int length) {
	int currOffset = 0;
	while (currOffset < length) {
		const int bytesRead = recv(socket, buffer + currOffset, length - currOffset, 0);
		if (bytesRead == 0) {
			Logger::get().log("Connection closed");
			throw std::runtime_error("Connection closed");
		}
		if (bytesRead == SOCKET_ERROR) {
			Logger::get().log("recv() failed: " + std::to_string(WSAGetLastError()));
			throw std::runtime_error("recv() failed: " + std::to_string(WSAGetLastError()));
		}
		currOffset += bytesRead;
	}
}

void MainWindow::actionShow_logs_clicked() {
	if (logsWindow && logsWindow->isVisible()) {
		logsWindow->activateWindow();

		return;
	}
	logsWindow = std::make_unique<LogsWindow>();
	logsWindow->show();
}

void MainWindow::_setStatusBarMessage(std::string msg) {
	ui->statusBar->showMessage(QString::fromStdString(msg));
}
