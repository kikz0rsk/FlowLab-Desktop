#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QStandardItemModel>
#include <thread>
#include <pcapplusplus/PcapFileDevice.h>

#include "proxy_service.h"
#include "tls_page.h"
#include "../sockets.h"

class DnsPage;
class ConnectionsPage;
class LogsWindow;
class ProxyService;
class DnsManager;

class QItemSelection;

QT_BEGIN_NAMESPACE
namespace Ui {
	class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
	Q_OBJECT

	public:
		MainWindow(std::shared_ptr<ProxyService> proxyService, QWidget *parent = nullptr);
		~MainWindow();

		void actionShow_logs_clicked();


	signals:
		void setStatusBarMessage(std::string msg);

	protected slots:
		void _setStatusBarMessage(std::string msg);

	private:
		Ui::MainWindow *ui;

		std::unique_ptr<LogsWindow> logsWindow;
		std::shared_ptr<DnsManager> dnsManager;
		std::shared_ptr<ProxyService> proxyService;
		DnsPage *dnsPage;
		TlsPage *tlsPage;
		ConnectionsPage *connectionsPage;
		boost::signals2::connection deviceConnectionSlot;
		std::unique_ptr<QMessageBox> errorMessage;

	protected:
		void closeEvent(QCloseEvent *event) override {
			QMainWindow::closeEvent(event);
			proxyService->stop();
		}

	public:
		[[nodiscard]] std::shared_ptr<DnsManager> getDnsManager() const {
				return dnsManager;
			}

			[[nodiscard]] std::shared_ptr<ProxyService> getProxyService() const {
				return proxyService;
			}

			[[nodiscard]] DnsPage * getDnsPage() const {
				return dnsPage;
			}

			[[nodiscard]] ConnectionsPage * getConnectionsPage() const {
				return connectionsPage;
			}

			void showEvent(QShowEvent *event) override;
};
#endif// MAINWINDOW_H
