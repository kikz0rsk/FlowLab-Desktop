#include <QDebug>
#include <iostream>
#include <utility>
#include <pcapplusplus/SystemUtils.h>
#include <QMessageBox>

#include "mainwindow.h"

#include "connections_page.h"
#include "./ui_mainwindow.h"
#include "logswindow.h"
#include "dnspage.h"
#include "tls_page.h"

MainWindow::MainWindow(std::shared_ptr<ProxyService> proxyService, QWidget *parent)	:
	QMainWindow(parent), ui(new Ui::MainWindow), proxyService(std::move(proxyService)) {
	ui->setupUi(this);

	dnsManager = this->proxyService->getDnsManager();
	connectionsPage = new ConnectionsPage(*this);
	dnsPage = new DnsPage(*this, dnsManager);
	tlsPage = new TlsPage(*this);

	ui->tabWidget->addTab(connectionsPage, "Connections");
	ui->tabWidget->addTab(dnsPage, "DNS");
	ui->tabWidget->addTab(tlsPage, "TLS");
	ui->statusBar->showMessage("Ready");
	connect(ui->actionShow_logs, &QAction::triggered, this, &MainWindow::actionShow_logs_clicked);
	connect(this, &MainWindow::setStatusBarMessage, this, &MainWindow::_setStatusBarMessage);

	this->deviceConnectionSlot = this->proxyService->getDeviceConnectionSignal().connect(
		[this](bool, std::shared_ptr<Client>, unsigned int numClients) {
			this->setStatusBarMessage(std::format("{} devices connected", numClients));
		}
	);
}

MainWindow::~MainWindow() {
	deviceConnectionSlot.disconnect();
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
			Logger::get().log("recv() failed: " + std::to_string(getLastSocketError()));
			throw std::runtime_error("recv() failed: " + std::to_string(getLastSocketError()));
		}
		currOffset += bytesRead;
	}
}

void MainWindow::showEvent(QShowEvent *event) {
	QMainWindow::showEvent(event);

	if (this->proxyService->isRunning()) {
		return;
	}

	try {
		this->proxyService->start();
	} catch (std::exception&) {
		this->errorMessage = std::make_unique<QMessageBox>(this);
		errorMessage->setWindowTitle("Error");
		errorMessage->setText("Failed to start proxy service. Check if the port is already in use or certificate files are missing.");
		errorMessage->setIcon(QMessageBox::Critical);
		errorMessage->setStandardButtons(QMessageBox::Ok);
		errorMessage->setDefaultButton(QMessageBox::Ok);
		errorMessage->setVisible(true);
		setStatusBarMessage("Error starting proxy service");
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
