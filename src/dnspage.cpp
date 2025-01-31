#include "dnspage.h"

#include <qstandarditemmodel.h>
#include "ui_dnspage.h"

DnsPage::DnsPage(MainWindow& mainWindow, std::shared_ptr<DnsManager> dnsManager, QWidget *parent) :
	QWidget(parent), ui(new Ui::DnsPage), mainWindow(mainWindow), dnsManager(std::move(dnsManager)) {
	ui->setupUi(this);
	addDnsCallback = std::make_shared<std::function<void (std::shared_ptr<DnsEntry>)>>(
		[this] (std::shared_ptr<DnsEntry> dns) {
			addDnsEntrySignal(std::move(dns));
		}
	);
	connect(this, &DnsPage::addDnsEntrySignal, this, &DnsPage::addDnsToTable);
	model = new QStandardItemModel(0, 1, this);
	model->setHorizontalHeaderLabels({"Domain"});
	this->ui->dnsList->setModel(model);
	this->dnsManager->registerEventCallback(addDnsCallback);
}

DnsPage::~DnsPage() {
	delete ui;
	dnsManager->unregisterEventCallback(addDnsCallback);
}

void DnsPage::addDnsToTable(std::shared_ptr<DnsEntry> dns) {
	auto *item = new QStandardItem(QString::fromStdString(dns->domain));
	item->setData(QVariant::fromValue(dns));
	model->insertRow(0, {item});
}
