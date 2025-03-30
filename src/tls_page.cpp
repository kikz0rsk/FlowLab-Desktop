#include "tls_page.h"

#include <utility>

#include "syntax_highlighter.h"
#include "ui_tls_page.h"
#include "tcp_connection.h"
#include "mainwindow.h"
#include "ndpi.h"
#include "proxy_service.h"

TlsPage::TlsPage(MainWindow& mainWindow, QWidget *parent) :
	QWidget(parent), mainWindow(mainWindow), ui(new Ui::TlsPage) {
	ui->setupUi(this);
	this->ui->enableTlsProxyCheckbox->setCheckState(mainWindow.getProxyService()->getEnableTlsRelay() == true ? Qt::CheckState::Checked : Qt::CheckState::Unchecked);
	connect(this, &TlsPage::addConnection, this, &TlsPage::onAddConnection);
	connect(this, &TlsPage::removeConnection, this, &TlsPage::onRemoveConnection);
	connect(ui->connectionsList, &QTreeView::activated, this, &TlsPage::listView_activated);
	connect(ui->connectionsList, &QTreeView::clicked, this, &TlsPage::listView_activated);
	connect(ui->utf8Button, &QPushButton::clicked, this, &TlsPage::utf8Button_clicked);
	connect(ui->utf16Button, &QPushButton::clicked, this, &TlsPage::utf16Button_clicked);
	connect(ui->enableTlsProxyCheckbox, &QCheckBox::checkStateChanged, this, &TlsPage::enableTlsRelayCheckbox_clicked);

	new FlowlabSyntaxHighlighter(ui->connectionStream);
	this->model.setHorizontalHeaderLabels({"ID", "Client IP", "Source IP", "Source Port", "Destination IP", "Destination Port", "Domain"});
	ui->connectionsList->setModel(&model);
	this->onTlsConnectionSignalConnection =
		mainWindow.getProxyService()->getConnectionManager()->getTlsConnectionAddedSignal().connect(
			[this](bool added, std::shared_ptr<TcpConnection> connection) {
				if (added) {
					addConnection(std::move(connection));
				} else {
					removeConnection(std::move(connection));
				}
			}
		);
}

TlsPage::~TlsPage() {
	this->onTlsConnectionSignalConnection.disconnect();
	delete ui;
}

void TlsPage::utf8Button_clicked() {
	showMode = 0;
	ui->utf8Button->setChecked(true);
	ui->utf16Button->setChecked(false);

	// update the view
	listView_activated(ui->connectionsList->currentIndex());
}

void TlsPage::utf16Button_clicked() {
	showMode = 1;
	ui->utf8Button->setChecked(false);
	ui->utf16Button->setChecked(true);

	// update the view
	listView_activated(ui->connectionsList->currentIndex());
}

void TlsPage::enableTlsRelayCheckbox_clicked(Qt::CheckState state) const {
	this->mainWindow.getProxyService()->setEnableTlsRelay(state == Qt::CheckState::Checked);
}

void TlsPage::listView_activated(const QModelIndex &index) {
	auto connection = model.index(index.row(), 1).data(Qt::UserRole + 1).value<std::shared_ptr<TcpConnection>>();
	if (!connection) {
		return;
	}

	auto readLock = connection->getReadLock();
	ui->sourceIpText->setText(QString::fromStdString(connection->getSrcIp().toString()));
	ui->destinationIpText->setText(QString::fromStdString(connection->getDstIp().toString()));
	ui->sourcePortText->setText(QString::number((uint) connection->getSrcPort()));
	ui->destinationPortText->setText(QString::number(connection->getDstPort()));
	if (showMode == 0) {
		std::vector<char> buffer(connection->getUnencryptedStream().begin(), connection->getUnencryptedStream().end());
		ui->connectionStream->setPlainText(QString::fromUtf8(buffer.data(), buffer.size()));
	} else {
		std::vector<char> buffer(connection->getUnencryptedStream().begin(), connection->getUnencryptedStream().end());
		if (buffer.size() % 2 == 1) {
			buffer.emplace_back(0);
		}
		const auto length = buffer.size() / 2;
		ui->connectionStream->setPlainText(QString::fromUtf16((const char16_t *) buffer.data(), length));
	}
	std::string domains;
	for (const auto& domain : connection->getDomains()) {
		domains += domain + ", ";
	}
	ui->domainsText->setText(QString::fromStdString(domains));

	ui->handshakeStatusText->setText(QString::fromStdString(connection->getTlsRelayStatus()));
	// std::array<char, 60> buffer{};
	// ndpi::ndpi_protocol2name(mainWindow.getProxyService()->getNdpiStruct(), connection->getNdpiProtocol(), buffer.data(), buffer.size());
	// ui->protocolText->setText(QString::fromUtf8(buffer.data()));
	// char *buf = ndpi::ndpi_serializer_get_buffer(ndpiSerializer.get(), &length);
	// ui->ndpiJson->setPlainText(QString::fromUtf8(buf, length));

}

void TlsPage::onAddConnection(std::shared_ptr<TcpConnection> connection) {
	auto *orderNum = new QStandardItem(QString::number(connection->getOrderNum()));
	auto *clientIp = new QStandardItem(QString::fromStdString(connection->getClient()->getClientIp().toString()));
	clientIp->setData(QVariant::fromValue(connection));
	auto *srcIp = new QStandardItem(QString::fromStdString(connection->getSrcIp().toString()));
	auto *srcPort = new QStandardItem(QString::number((uint) connection->getSrcPort()));
	auto *dstIp = new QStandardItem(QString::fromStdString(connection->getDstIp().toString()));
	auto *dstPort = new QStandardItem(QString::number(connection->getDstPort()));
	std::string domains;
	for (const auto& domain : connection->getDomains()) {
		domains += domain + ", ";
	}
	auto *domain = new QStandardItem(QString::fromStdString(connection->getServerNameIndication()));
	model.insertRow(0, {orderNum, clientIp, srcIp, srcPort, dstIp, dstPort, domain});
}

void TlsPage::onRemoveConnection(std::shared_ptr<TcpConnection> connection) {
	for (int i = 0; i < model.rowCount(); i++) {
		auto index = model.index(i, 1);
		auto conn = index.data(Qt::UserRole + 1).value<std::shared_ptr<Connection>>();
		if (conn == connection) {
			model.removeRow(i);

			return;
		}
	}
}
