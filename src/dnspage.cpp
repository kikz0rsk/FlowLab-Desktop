#include "dnspage.h"

#include <qstandarditemmodel.h>
#include "ui_dnspage.h"

DnsPage::DnsPage(MainWindow& mainWindow, DnsManager& dnsManager, QWidget *parent) :
	QWidget(parent), ui(new Ui::DnsPage), mainWindow(mainWindow), dnsManager(dnsManager) {
	ui->setupUi(this);
	addDnsCallback = std::make_shared<std::function<void (const DnsEntry&)>>(
		[this] (const DnsEntry &dns) {
			addDnsEntrySignal(dns);
		}
	);
	connect(this, &DnsPage::addDnsEntrySignal, this, &DnsPage::addDnsToTable);
	model = new QStandardItemModel(0, 1, this);
	model->setHorizontalHeaderLabels({"Domain"});
}

DnsPage::~DnsPage() {
	delete ui;
	dnsManager.unregisterEventCallback(addDnsCallback);
}

void DnsPage::addDnsToTable(const DnsEntry &dns) {
	auto *item = new QStandardItem();
	item->setText(QString::fromStdString(dns.domain));
	item->setData(QVariant::fromValue(dns));
	model->insertRow(0, item);
}
