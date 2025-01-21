#ifndef DNSPAGE_H
#define DNSPAGE_H

#include <QStandardItemModel>
#include <QWidget>

#include "dns_manager.h"

class MainWindow;

namespace Ui {
	class DnsPage;
}

class DnsPage : public QWidget
{
	Q_OBJECT

	public:
		explicit DnsPage(MainWindow& mainWindow, DnsManager& dnsManager, QWidget *parent = nullptr);
		~DnsPage();

	signals:
		void addDnsEntrySignal(const DnsEntry& dns);

	private slots:
		void addDnsToTable(const DnsEntry& dns);

	private:
		Ui::DnsPage *ui;
		MainWindow& mainWindow;
		DnsManager& dnsManager;
		QStandardItemModel* model;
		std::shared_ptr<std::function<void (const DnsEntry&)>> addDnsCallback;
};

#endif// DNSPAGE_H
