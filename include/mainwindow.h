#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include <thread>
#include <pcapplusplus/PcapFileDevice.h>

#include "connection.h"
#include "connection_manager.h"
#include "logswindow.h"

class DnsPage;
class ConnectionsPage;

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
		MainWindow(QWidget *parent = nullptr);
		~MainWindow();

		void actionShow_logs_clicked();
		ndpi::ndpi_detection_module_struct *ndpiStruct;

	signals:
		void setStatusBarMessage(std::string msg);

	protected slots:
		void _setStatusBarMessage(std::string msg);

	private:
		Ui::MainWindow *ui;
		std::thread thread;
		SOCKET socket;
		std::atomic_bool stopFlag = false;
		std::unique_ptr<LogsWindow> logsWindow;
		ConnectionManager connections;

		DnsPage *dnsPage;
		ConnectionsPage *connectionsPage;

		std::shared_ptr<pcpp::PcapFileWriterDevice> pcapWriter;

		void threadRoutine();
		static std::string getKey(const pcpp::IPAddress &src_ip, const pcpp::IPAddress &dst_ip, uint16_t src_port, uint16_t dst_port, Protocol protocol);
		void packetLoop();
		void sendFromDevice();
};
#endif// MAINWINDOW_H
