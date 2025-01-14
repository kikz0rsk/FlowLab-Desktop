#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <thread>

#include <QStandardItemModel>

#include "connection.h"
#include "connection_manager.h"
#include "logswindow.h"
#include <pcapplusplus/PcapFileDevice.h>

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

    void listView_activated(const QModelIndex &index);
    void actionShow_logs_clicked();

signals:
    void setStatusBarMessage(std::string msg);

protected slots:
    void _setStatusBarMessage(std::string msg);
    void utf8Button_clicked();
    void utf16Button_clicked();

private:
    Ui::MainWindow *ui;
    std::thread thread;
    // std::unordered_map<std::string, std::shared_ptr<Connection>> connections;
    QStandardItemModel model;
    SOCKET socket;
    std::atomic_bool stopFlag = false;
    std::unique_ptr<LogsWindow> logsWindow;
    int showMode = 0;
    ConnectionManager connections;
    ndpi::ndpi_detection_module_struct *ndpiStruct;
    std::shared_ptr<pcpp::PcapFileWriterDevice> pcapWriter;

    void threadRoutine();
    static std::string getKey(const pcpp::IPAddress &src_ip, const pcpp::IPAddress &dst_ip, uint16_t src_port, uint16_t dst_port, Protocol protocol);
    void packetLoop();
    void sendFromDevice();
};
#endif // MAINWINDOW_H
