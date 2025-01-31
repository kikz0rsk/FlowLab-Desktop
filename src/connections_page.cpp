#include "connections_page.h"

#include "syntax_highlighter.h"
#include "ui_connections_page.h"
#include "ndpi.h"
#include "tcp_connection.h"
#include "mainwindow.h"

ConnectionsPage::ConnectionsPage(MainWindow& mainWindow, QWidget *parent) :
	QWidget(parent), mainWindow(mainWindow), ui(new Ui::ConnectionsPage) {
	ui->setupUi(this);
	connect(ui->connectionsList, &QTreeView::activated, this, &ConnectionsPage::listView_activated);
	connect(ui->connectionsList, &QTreeView::clicked, this, &ConnectionsPage::listView_activated);
	connect(ui->utf8Button, &QPushButton::clicked, this, &ConnectionsPage::utf8Button_clicked);
	connect(ui->utf16Button, &QPushButton::clicked, this, &ConnectionsPage::utf16Button_clicked);

	new FlowlabSyntaxHighlighter(ui->connectionStream);
	this->model.setHorizontalHeaderLabels({"Source IP", "Source Port", "Destination IP", "Destination Port", "L2 Protocol"});
	ui->connectionsList->setModel(&model);
}

ConnectionsPage::~ConnectionsPage() {
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
	auto connection = model.index(index.row(), 0).data(Qt::UserRole + 1).value<std::shared_ptr<Connection>>();
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

	std::unique_ptr<ndpi::ndpi_serializer> ndpiSerializer = std::make_unique<ndpi::ndpi_serializer>();
	ndpi::ndpi_init_serializer(ndpiSerializer.get(), ndpi::ndpi_serialization_format::ndpi_serialization_format_json);
	ndpi::ndpi_dpi2json(mainWindow.ndpiStruct, connection->getNdpiFlow(), connection->getNdpiProtocol(), ndpiSerializer.get());
	std::uint32_t length{};
	char* buf = ndpi::ndpi_serializer_get_buffer(ndpiSerializer.get(), &length);
	ui->ndpiJson->setPlainText(QString::fromUtf8(buf, length));

	if (auto tcpConnection = std::dynamic_pointer_cast<TcpConnection>(connection)) {
		ui->tcpStatusText->setText(QString::fromStdString(remoteSocketStatusToString(tcpConnection->getRemoteSocketStatus())));
	} else {
		ui->tcpStatusText->setText("");
	}
}

void ConnectionsPage::addConnection(std::shared_ptr<Connection> connection) {
	// auto* row = new QStandardItem();
	auto* srcIp = new QStandardItem(QString::fromStdString(connection->getSrcIp().toString()));
	srcIp->setData(QVariant::fromValue(connection));
	auto* srcPort = new QStandardItem(QString::number((uint) connection->getSrcPort()));
	auto* dstIp = new QStandardItem(QString::fromStdString(connection->getDstIp().toString()));
	auto* dstPort = new QStandardItem(QString::number(connection->getDstPort()));
	auto* protocol = new QStandardItem(connection->getProtocol() == Protocol::TCP ? "TCP" : "UDP");
	// row->appendRow({srcIp, srcPort, dstIp, dstPort, protocol});
	// row->setData(QVariant::fromValue(connection));
	// auto *item = new QStandardItem(
	// 	QString::fromStdString(
	// 		connection->getSrcIp().toString()
	// 			+ ":" + std::to_string(connection->getSrcPort()) + " -> "
	// 			+ connection->getDstIp().toString() + ":" + std::to_string(connection->getDstPort())
	// 			+ " " + (connection->getProtocol() == Protocol::TCP ? "TCP" : "UDP")
	// 	)
	// );
	model.insertRow(0, {srcIp, srcPort, dstIp, dstPort, protocol});
}
