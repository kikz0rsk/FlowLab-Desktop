#include "connections_page.h"

#include <utility>

#include "syntax_highlighter.h"
#include "ui_connections_page.h"
#include "ndpi.h"
#include "tcp_connection.h"
#include "mainwindow.h"

ConnectionsPage::ConnectionsPage(MainWindow& mainWindow, QWidget *parent) :
	QWidget(parent), mainWindow(mainWindow), ui(new Ui::ConnectionsPage) {
	ui->setupUi(this);
	connect(this, &ConnectionsPage::addConnection, this, &ConnectionsPage::onAddConnection);
	connect(this, &ConnectionsPage::removeConnection, this, &ConnectionsPage::onRemoveConnection);
	connect(ui->connectionsList, &QTreeView::activated, this, &ConnectionsPage::listView_activated);
	connect(ui->connectionsList, &QTreeView::clicked, this, &ConnectionsPage::listView_activated);
	connect(ui->utf8Button, &QPushButton::clicked, this, &ConnectionsPage::utf8Button_clicked);
	connect(ui->utf16Button, &QPushButton::clicked, this, &ConnectionsPage::utf16Button_clicked);

	new FlowlabSyntaxHighlighter(ui->connectionStream);
	this->model.setHorizontalHeaderLabels({"ID", "Client IP", "Source IP", "Source Port", "Destination IP", "Destination Port", "L4 Protocol"});
	ui->connectionsList->setModel(&model);
	this->onConnectionSignalConnection =
		mainWindow.getProxyService()->getConnectionManager()->getConnectionAddedSignal().connect(
			[this](bool added, std::shared_ptr<Connection> connection) {
				if (added) {
					addConnection(std::move(connection));
				} else {
					removeConnection(std::move(connection));
				}
			}
		);
}

ConnectionsPage::~ConnectionsPage() {
	this->onConnectionSignalConnection.disconnect();
	delete ui;
}

void ConnectionsPage::utf8Button_clicked() {
	showMode = 0;
	ui->utf8Button->setChecked(true);
	ui->utf16Button->setChecked(false);

	// update the view
	listView_activated(ui->connectionsList->currentIndex());
}

void ConnectionsPage::utf16Button_clicked() {
	showMode = 1;
	ui->utf8Button->setChecked(false);
	ui->utf16Button->setChecked(true);

	// update the view
	listView_activated(ui->connectionsList->currentIndex());
}

void ConnectionsPage::listView_activated(const QModelIndex &index) {
	auto connection = model.index(index.row(), 1).data(Qt::UserRole + 1).value<std::shared_ptr<Connection>>();
	if (!connection) {
		return;
	}

	ui->sentText->setText(QString::number(connection->getSentPacketCount()) + " packets (" + QString::number(connection->getSentBytes()) + " bytes)");
	ui->receivedText->setText(QString::number(connection->getReceivedPacketCount()) + " packets (" + QString::number(connection->getReceivedBytes()) + " bytes)");
	auto readLock = connection->getReadLock();
	ui->sourceIpText->setText(QString::fromStdString(connection->getSrcIp().toString()));
	ui->destinationIpText->setText(QString::fromStdString(connection->getDstIp().toString()));
	ui->sourcePortText->setText(QString::number((uint) connection->getSrcPort()));
	ui->destinationPortText->setText(QString::number(connection->getDstPort()));
	if (showMode == 0) {
		std::vector<char> buffer(connection->getDataStream().begin(), connection->getDataStream().end());
		ui->connectionStream->setPlainText(QString::fromUtf8(buffer.data(), buffer.size()));
	} else {
		std::vector<char> buffer(connection->getDataStream().begin(), connection->getDataStream().end());
		if (buffer.size() % 2 == 1) {
			buffer.emplace_back(0);
		}
		const auto length = buffer.size() / 2;
		ui->connectionStream->setPlainText(QString::fromUtf16((const char16_t *) buffer.data(), length));
	}

	std::vector<char> buffer(60);
	if (connection->getNdpiProtocol().has_value()) {
		ndpi::ndpi_protocol2name(mainWindow.getProxyService()->getNdpiStruct(), *connection->getNdpiProtocol(), buffer.data(), buffer.size());
		ui->protocolText->setText(QString::fromUtf8(buffer.data()));

		std::unique_ptr<ndpi::ndpi_serializer> ndpiSerializer = std::make_unique<ndpi::ndpi_serializer>();
		ndpi::ndpi_init_serializer(ndpiSerializer.get(), ndpi::ndpi_serialization_format::ndpi_serialization_format_json);
		ndpi::ndpi_dpi2json(mainWindow.getProxyService()->getNdpiStruct(), connection->getNdpiFlow().get(), *connection->getNdpiProtocol(), ndpiSerializer.get());
		std::uint32_t length{};
		char *buf = ndpi::ndpi_serializer_get_buffer(ndpiSerializer.get(), &length);
		ui->ndpiJson->setPlainText(QString::fromUtf8(buf, length));
	} else {
		ui->ndpiJson->clear();
		ui->protocolText->setText("Unknown");
	}

	if (auto tcpConnection = std::dynamic_pointer_cast<TcpConnection>(connection)) {
		ui->tcpStatusText->setText(QString::fromStdString(remoteSocketStatusToString(tcpConnection->getRemoteSocketStatus())));
	} else {
		ui->tcpStatusText->setText("");
	}
}

void ConnectionsPage::onAddConnection(std::shared_ptr<Connection> connection) {
	auto *orderNum = new QStandardItem(QString::number(connection->getOrderNum()));
	auto *clientIp = new QStandardItem(QString::fromStdString(connection->getClient()->getClientIp().toString()));
	clientIp->setData(QVariant::fromValue(connection));
	auto *srcIp = new QStandardItem(QString::fromStdString(connection->getSrcIp().toString()));
	auto *srcPort = new QStandardItem(QString::number((uint) connection->getSrcPort()));
	auto *dstIp = new QStandardItem(QString::fromStdString(connection->getDstIp().toString()));
	auto *dstPort = new QStandardItem(QString::number(connection->getDstPort()));
	auto *protocol = new QStandardItem(connection->getProtocol() == Protocol::TCP ? "TCP" : "UDP");
	model.insertRow(0, {orderNum, clientIp, srcIp, srcPort, dstIp, dstPort, protocol});
}

void ConnectionsPage::onRemoveConnection(std::shared_ptr<Connection> connection) {
	for (int i = 0; i < model.rowCount(); i++) {
		auto index = model.index(i, 1);
		auto conn = index.data(Qt::UserRole + 1).value<std::shared_ptr<Connection>>();
		if (conn == connection) {
			model.removeRow(i);

			return;
		}
	}
}
