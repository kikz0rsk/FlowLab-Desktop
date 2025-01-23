#include "connections_page.h"

#include "syntax_highlighter.h"
#include "ui_connections_page.h"
#include "ndpi.h"
#include "tcp_connection.h"
#include "mainwindow.h"

ConnectionsPage::ConnectionsPage(MainWindow& mainWindow, QWidget *parent) :
	QWidget(parent), mainWindow(mainWindow), ui(new Ui::ConnectionsPage) {
	ui->setupUi(this);
	connect(ui->listView, &QListView::activated, this, &ConnectionsPage::listView_activated);
	connect(ui->listView, &QListView::clicked, this, &ConnectionsPage::listView_activated);
	connect(ui->utf8Button, &QPushButton::clicked, this, &ConnectionsPage::utf8Button_clicked);
	connect(ui->utf16Button, &QPushButton::clicked, this, &ConnectionsPage::utf16Button_clicked);

	new FlowlabSyntaxHighlighter(ui->connectionStream);
	ui->listView->setModel(&model);
}

ConnectionsPage::~ConnectionsPage() {
	delete ui;
}

void ConnectionsPage::utf8Button_clicked() {
	showMode = 0;
	ui->utf8Button->setChecked(true);
	ui->utf16Button->setChecked(false);

	// update the view
	listView_activated(ui->listView->currentIndex());
}

void ConnectionsPage::utf16Button_clicked() {
	showMode = 1;
	ui->utf8Button->setChecked(false);
	ui->utf16Button->setChecked(true);

	// update the view
	listView_activated(ui->listView->currentIndex());
}

void ConnectionsPage::listView_activated(const QModelIndex &index) {
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
	ndpi::ndpi_protocol2name(mainWindow.ndpiStruct, connection->getNdpiProtocol(), buffer.data(), buffer.size());
	ui->protocolText->setText(QString::fromUtf8(buffer.data()));

	if (auto tcpConnection = std::dynamic_pointer_cast<TcpConnection>(connection)) {
		ui->tcpStatusText->setText(QString::fromStdString(remoteSocketStatusToString(tcpConnection->getRemoteSocketStatus())));
	} else {
		ui->tcpStatusText->setText("");
	}
}

void ConnectionsPage::addConnection(std::shared_ptr<Connection> connection) {
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
