#pragma once

#include <QStandardItemModel>
#include <QWidget>

#include "dns_manager.h"
#include "connection_manager.h"
#include "ui_tls_page.h"

class TcpConnection;
class MainWindow;

namespace Ui {
	class TlsPage;
}

class TlsPage : public QWidget
{
	Q_OBJECT

	public:
		explicit TlsPage(MainWindow& mainWindow, QWidget *parent = nullptr);
		~TlsPage();

		void listView_activated(const QModelIndex &index);
		void addConnection(std::shared_ptr<TcpConnection> connection);
		void removeConnection(std::shared_ptr<TcpConnection> connection);

	signals:
		void addDnsEntrySignal(std::shared_ptr<DnsEntry> dns);

	protected slots:
		void utf8Button_clicked();
		void utf16Button_clicked();
		void enableTlsRelayCheckbox_clicked(Qt::CheckState state) const;

	private:
		MainWindow& mainWindow;
		Ui::TlsPage *ui;
		QStandardItemModel model;
		int showMode = 0;
		ConnectionManager::OnTlsConnectionCallback onTlsConnectionCallback;
};
