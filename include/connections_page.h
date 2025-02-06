#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include <QStandardItemModel>
#include <QWidget>
#include "connection.h"
#include "proxy_service.h"

class MainWindow;

namespace Ui {
	class ConnectionsPage;
}

class ConnectionsPage : public QWidget
{
	Q_OBJECT

	public:
		explicit ConnectionsPage(MainWindow& mainWindow, QWidget *parent = nullptr);
		~ConnectionsPage();

		void listView_activated(const QModelIndex &index);
		void addConnection(std::shared_ptr<Connection> connection);

	protected slots:
		void utf8Button_clicked();
		void utf16Button_clicked();

	private:
		MainWindow& mainWindow;
		Ui::ConnectionsPage *ui;
		QStandardItemModel model;
		int showMode = 0;
		ProxyService::OnConnectionCallback onConnectionCallback;
};

#endif// CONNECTIONS_H
