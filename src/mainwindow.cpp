#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QDebug>
#include <array>
#include <iostream>
#include <winsock2.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>

#include "logger.h"
#include "logswindow.h"
#include "packet_utils.h"
#include "tcp_connection.h"
#include "udp_connection.h"

MainWindow::MainWindow(QWidget *parent)	:
	QMainWindow(parent)
	, ui(new Ui::MainWindow) {
	ui->setupUi(this);
	connect(ui->listView, &QListView::activated, this, &MainWindow::listView_activated);
	connect(ui->listView, &QListView::clicked, this, &MainWindow::listView_activated);
	connect(ui->actionShow_logs, &QAction::triggered, this, &MainWindow::actionShow_logs_clicked);
	connect(this, &MainWindow::setStatusBarMessage, this, &MainWindow::_setStatusBarMessage);

	connect(ui->utf8Button, &QPushButton::clicked, this, &MainWindow::utf8Button_clicked);
	connect(ui->utf16Button, &QPushButton::clicked, this, &MainWindow::utf16Button_clicked);

	ndpiStruct = ndpi::ndpi_init_detection_module(nullptr);
	if (ndpiStruct == nullptr) {
		throw std::runtime_error("Failed to initialize nDPI");
	}

	ndpi::ndpi_protocol_bitmask_struct_t all;
	NDPI_BITMASK_SET_ALL(all);
	ndpi::ndpi_set_protocol_detection_bitmask2(ndpiStruct, &all);
	ndpi::ndpi_finalize_initialization(ndpiStruct);

	ui->listView->setModel(&model);
	thread = std::thread(
		[this] {
			threadRoutine();
		}
	);
}

MainWindow::~MainWindow() {
	stopFlag = true;
	thread.join();
	closesocket(socket);
	ndpi::ndpi_exit_detection_module(ndpiStruct);
	delete ui;
}

void MainWindow::threadRoutine() {
	WSADATA wsaData;

	int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (res != 0) {
		printf("WSAStartup failed: %d\n", res);
		WSACleanup();

		return;
	}

	socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socket == INVALID_SOCKET) {
		std::cerr << "socket() failed: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	auto addr = sockaddr_in{AF_INET, htons(20'000), INADDR_ANY};
	res = bind(socket, (SOCKADDR *) &addr, sizeof(sockaddr_in));
	if (res == SOCKET_ERROR) {
		std::cerr << "bind() failed: " << WSAGetLastError() << std::endl;
		WSACleanup();

		return;
	}

	setStatusBarMessage("Socket ready on port " + std::to_string(ntohs(addr.sin_port)));

	packetLoop();
}

std::string MainWindow::getKey(const pcpp::IPAddress &src_ip, const pcpp::IPAddress &dst_ip, uint16_t src_port, uint16_t dst_port, Protocol protocol) {
	return src_ip.toString() + "," + std::to_string(src_port) + "," + dst_ip.toString() + "," + std::to_string(dst_port) + "," + (protocol == Protocol::TCP ? "tcp" : "udp");
}

void MainWindow::packetLoop() {
	while (!stopFlag.load()) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(socket, &fds);
		for (const auto &conn: connections.getConnections()) {
			if (conn.second->getRemoteSocketStatus() == RemoteSocketStatus::CLOSED) {
				continue;
			}
			FD_SET(conn.second->getSocket(), &fds);
		}

		const TIMEVAL timeout{0, 500'000};
		select(0, &fds, nullptr, nullptr, &timeout);

		if (FD_ISSET(socket, &fds)) {
			sendFromDevice();
			Logger::get().log({});
		}

		for (auto &conn: connections.getConnections()) {
			if (!FD_ISSET(conn.second->getSocket(), &fds)) {
				continue;
			}

			const auto data = conn.second->read();
			if (data.empty()) {
				continue;
			}

			Logger::get().log("Read " + std::to_string(data.size()) + " bytes from socket");

			size_t offset = 0;
			while (offset < data.size()) {
				const unsigned int length = std::min(offset + 1400, data.size()) - offset;
				const auto packet = conn.second->encapsulateResponseDataToPacket(std::vector(data.begin() + offset, data.begin() + offset + length));
				if (!packet) {
					break;
				}

				Logger::get().log(
					"Sending to: " + conn.second->getOriginHostIp().toString() + ":" + std::to_string(conn.second->getOriginHostPort()) + " " + PacketUtils::toString(*packet)
				);

				sendto(
					socket,
					reinterpret_cast<const char *>(packet->getRawPacketReadOnly()->getRawData()),
					packet->getRawPacketReadOnly()->getRawDataLen(),
					0,
					(SOCKADDR *) &conn.second->getDestSockAddr(),
					sizeof(conn.second->getDestSockAddr())
				);

				if (auto tcpConn = std::dynamic_pointer_cast<TcpConnection>(conn.second)) {
					tcpConn->getOurSequenceNumber().fetch_add(length);
				}
				offset += length;
			}
			Logger::get().log({});
		}
	}
}

void MainWindow::sendFromDevice() {
	std::array<char, 65535> buffer{};

	sockaddr_in from{};
	int from_size = sizeof(from);
	int length = recvfrom(socket, buffer.data(), buffer.size(), 0, (SOCKADDR *) &from, &from_size);
	if (length == SOCKET_ERROR) {
		Logger::get().log("sendFromDevice() recvfrom() failed: " + std::to_string(WSAGetLastError()));

		return;
	}

	timeval time{};
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
					tcpLayer->getTcpHeader()->ackNumber = tcpLayer->getTcpHeader()->sequenceNumber;
					tcpLayer->getTcpHeader()->sequenceNumber = tcpLayer->getTcpHeader()->ackNumber;
					tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(4096);

					pcpp::Packet rstPacket(50);
					rstPacket.addLayer(ipLayer, true);
					rstPacket.addLayer(tcpLayer, true);

					rstPacket.computeCalculateFields();

					sendto(
						socket,
						reinterpret_cast<const char *>(rstPacket.getRawPacketReadOnly()->getRawData()),
						rstPacket.getRawPacketReadOnly()->getRawDataLen(),
						0,
						(SOCKADDR *) &from,
						sizeof(from)
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
				socket,
				ndpiStruct
			);
			connections.addConnection(connection);
		} else {
			connection = std::make_shared<UdpConnection>(
				pcpp::IPAddress(pcpp::IPv4Address((uint32_t) from.sin_addr.S_un.S_addr)),
				ntohs(from.sin_port),
				ipv4Layer->getSrcIPAddress(),
				ipv4Layer->getDstIPAddress(),
				srcPort,
				dstPort,
				socket,
				ndpiStruct
			);
			connections.addConnection(connection);
		}
		newConnection = true;
	}

	if (newConnection) {
		auto *item = new QStandardItem(
			QString::fromStdString(
				connection->getSrcIp().toString()
				+ ":" + std::to_string(connection->getSrcPort()) + " -> "
				+ connection->getDstIp().toString() + ":" + std::to_string(connection->getDstPort())
				+ " " + (connection->getProtocol() == Protocol::TCP ? "TCP" : "UDP")
			)
		);
		item->setData(QVariant::fromValue(connection));
		model.insertRow(0, item);
	}

	connection->processPacketFromDevice(ipv4Layer);
	Logger::get().log({});
}

void MainWindow::listView_activated(const QModelIndex &index) {
	auto connection = index.data(Qt::UserRole + 1).value<std::shared_ptr<Connection>>();
	if (!connection) {
		return;
	}

	auto readLock = connection->getReadLock();
	ui->sourceIpText->setText(QString::fromStdString(connection->getSrcIp().toString()));
	ui->destinationIpText->setText(QString::fromStdString(connection->getDstIp().toString()));
	ui->sourcePortText->setText(QString::number((uint) connection->getSrcPort()));
	ui->destinationPortText->setText(QString::number(connection->getDstPort()));
	if (showMode == 0) {
		ui->connectionStream->setPlainText(QString::fromUtf8((const char *) connection->getDataStream().data(), connection->getDataStream().size()));
	} else {
		auto vec = std::vector(connection->getDataStream().data(), connection->getDataStream().data() + connection->getDataStream().size());
		if (vec.size() % 2 == 1) {
			vec.emplace_back(0);
		}
		const auto length = vec.size() / 2;
		ui->connectionStream->setPlainText(QString::fromUtf16((const char16_t *) connection->getDataStream().data(), length));
	}

	std::array<char, 60> buffer{};
	ndpi::ndpi_protocol2name(ndpiStruct, connection->getNdpiProtocol(), buffer.data(), buffer.size());
	ui->protocolText->setText(QString::fromUtf8(buffer.data()));

	if (auto tcpConnection = std::dynamic_pointer_cast<TcpConnection>(connection)) {
		ui->tcpStatusText->setText(QString::fromStdString(remoteSocketStatusToString(tcpConnection->getRemoteSocketStatus())));
	} else {
		ui->tcpStatusText->setText("");
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

void MainWindow::utf8Button_clicked() {
	showMode = 0;
	ui->utf8Button->setChecked(true);
	ui->utf16Button->setChecked(false);

	// update the view
	listView_activated(ui->listView->currentIndex());
}

void MainWindow::utf16Button_clicked() {
	showMode = 1;
	ui->utf8Button->setChecked(false);
	ui->utf16Button->setChecked(true);

	// update the view
	listView_activated(ui->listView->currentIndex());
}
