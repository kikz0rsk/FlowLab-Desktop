#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QWidget>
#include "connection.h"
#include "connection_manager.h"
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

	signals:
		void addConnection(std::shared_ptr<Connection> connection);
		void removeConnection(std::shared_ptr<Connection> connection);

	protected slots:
		void onAddConnection(std::shared_ptr<Connection> connection);
		void onRemoveConnection(std::shared_ptr<Connection> connection);
		void listView_activated(const QModelIndex &index);
		void utf8Button_clicked();
		void utf16Button_clicked();

	private:
		MainWindow& mainWindow;
		Ui::ConnectionsPage *ui;
		QStandardItemModel model;
		QSortFilterProxyModel* proxy;
		int showMode = 0;
		boost::signals2::connection onConnectionSignalConnection;
		const QSet<int> numericCols = { 0, 3, 5 };
};

#endif// CONNECTIONS_H
