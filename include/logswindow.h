#ifndef LOGSWINDOW_H
#define LOGSWINDOW_H

#include <QWidget>
#include <ui_logswindow.h>

#include "logger.h"

namespace Ui {
	class LogsWindow;
}

class LogsWindow : public QWidget
{
	Q_OBJECT

	public:
		explicit LogsWindow(QWidget *parent = nullptr);
		~LogsWindow();

	signals:
		void onLog(std::string log);

	public slots:
		void appendLog(std::string log);

	private:
		Ui::LogsWindow *ui;
		Logger::OnLogCallback logCallback;
};

#endif// LOGSWINDOW_H
