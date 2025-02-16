#include <QDebug>
#include <array>
#include <iostream>
#include <utility>
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

MainWindow::MainWindow(std::shared_ptr<ProxyService> proxyService, QWidget *parent)	:
	QMainWindow(parent), ui(new Ui::MainWindow), proxyService(std::move(proxyService)) {
	ui->setupUi(this);

	dnsManager = this->proxyService->getDnsManager();
	connectionsPage = new ConnectionsPage(*this);
	dnsPage = new DnsPage(*this, dnsManager);

	ui->tabWidget->addTab(connectionsPage, "Connections");
	ui->tabWidget->addTab(dnsPage, "DNS");

	connect(ui->actionShow_logs, &QAction::triggered, this, &MainWindow::actionShow_logs_clicked);
	connect(this, &MainWindow::setStatusBarMessage, this, &MainWindow::_setStatusBarMessage);
}

MainWindow::~MainWindow() {
	delete ui;
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
