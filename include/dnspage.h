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
		explicit DnsPage(MainWindow& mainWindow, std::shared_ptr<DnsManager> dnsManager, QWidget *parent = nullptr);
		~DnsPage();

	signals:
		void addDnsEntrySignal(std::shared_ptr<DnsEntry> dns);

	private slots:
		void addDnsToTable(std::shared_ptr<DnsEntry> dns);
		void changeSelectedEntry(const QModelIndex &index);

	private:
		Ui::DnsPage *ui;
		MainWindow& mainWindow;
		std::shared_ptr<DnsManager> dnsManager;
		QStandardItemModel* model;
		std::shared_ptr<std::function<void (std::shared_ptr<DnsEntry>)>> addDnsCallback;
};

#endif// DNSPAGE_H
