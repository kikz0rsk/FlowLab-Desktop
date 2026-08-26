#include "gui/mainwindow.h"

#include <QApplication>
#include <csignal>

#include "proxy_service.h"
#include "tracy/Tracy.hpp"

int main(int argc, char *argv[]) {
#ifdef linux
	std::signal(SIGPIPE, SIG_IGN);
#endif
	TracyNoop;
	auto proxyService = std::make_shared<ProxyService>();
	QApplication a(argc, argv);
	MainWindow w(proxyService);
	w.show();

	return a.exec();
}
