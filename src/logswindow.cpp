#include "logswindow.h"

#include "logger.h"
#include "ui_logswindow.h"

LogsWindow::LogsWindow(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::LogsWindow)
{
    ui->setupUi(this);
    logCallback = std::make_shared<std::function<void(const std::string &)>>([this] (const std::string &log) {
        emit onLog(log);
    });
    connect(this, &LogsWindow::onLog, this, &LogsWindow::appendLog);
    Logger::get().registerEventCallback(logCallback);

}

LogsWindow::~LogsWindow()
{
    Logger::get().unregisterEventCallback(logCallback);
    delete ui;
}

void LogsWindow::appendLog(const std::string &log) {
    ui->logsTextEdit->appendPlainText(QString::fromStdString(log));
}
