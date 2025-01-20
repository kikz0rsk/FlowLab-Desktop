#ifndef DNSPAGE_H
#define DNSPAGE_H

#include <QWidget>

class MainWindow;

namespace Ui {
	class DnsPage;
}

class DnsPage : public QWidget
{
	Q_OBJECT

	public:
		explicit DnsPage(MainWindow& mainWindow, QWidget *parent = nullptr);
		~DnsPage();

	private:
		Ui::DnsPage *ui;
		MainWindow& mainWindow;
};

#endif// DNSPAGE_H
