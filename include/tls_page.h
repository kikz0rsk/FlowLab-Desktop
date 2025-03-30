#pragma once

#include <QStandardItemModel>
#include <QWidget>

#include "connection_manager.h"
#include "ui_tls_page.h"

struct DnsEntry;
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

	signals:
		void addConnection(std::shared_ptr<TcpConnection> connection);
		void removeConnection(std::shared_ptr<TcpConnection> connection);

	protected slots:
		void onAddConnection(std::shared_ptr<TcpConnection> connection);
		void onRemoveConnection(std::shared_ptr<TcpConnection> connection);
		void listView_activated(const QModelIndex &index);
		void utf8Button_clicked();
		void utf16Button_clicked();
		void enableTlsRelayCheckbox_clicked(Qt::CheckState state) const;

	private:
		MainWindow& mainWindow;
		Ui::TlsPage *ui;
		QStandardItemModel model;
		int showMode = 0;
		boost::signals2::connection onTlsConnectionSignalConnection;
};
