#include "dnspage.h"

#include "ui_dnspage.h"
#include "dns_entry.h"
#include "dns_manager.h"

DnsPage::DnsPage(MainWindow& mainWindow, std::shared_ptr<DnsManager> dnsManager, QWidget *parent) :
	QWidget(parent), ui(new Ui::DnsPage), mainWindow(mainWindow), dnsManager(std::move(dnsManager)) {
	ui->setupUi(this);
	connect(this, &DnsPage::addDnsEntrySignal, this, &DnsPage::addDnsToTable);
	connect(ui->dnsList, &QTreeView::clicked, this, &DnsPage::changeSelectedEntry);
	model = new QStandardItemModel(0, 1, this);
	model->setHorizontalHeaderLabels({"Domain"});
	this->ui->dnsList->setModel(model);
	this->addDnsSignalConnection =
		this->dnsManager->getOnAddSignal().connect(
			[this] (std::shared_ptr<DnsEntry> dns) {
				addDnsEntrySignal(std::move(dns));
			}
		);
}

DnsPage::~DnsPage() {
	this->addDnsSignalConnection.disconnect();
	delete ui;
}

void DnsPage::addDnsToTable(std::shared_ptr<DnsEntry> dns) {
	auto *item = new QStandardItem(QString::fromStdString(dns->domain));
	item->setData(QVariant::fromValue(dns));
	model->insertRow(0, {item});
}

void DnsPage::changeSelectedEntry(const QModelIndex &index) {
	auto dns = model->index(index.row(), 0).data(Qt::UserRole + 1).value<std::shared_ptr<DnsEntry>>();
	if (!dns) {
		return;
	}

	ui->domainText->setText(QString::fromStdString(dns->domain));
	ui->answersText->clear();
	std::string answers;
	for (const auto& answer : dns->answers) {
		answers += answer + "\n";
	}
	ui->answersText->setText(QString::fromStdString(answers));
}
