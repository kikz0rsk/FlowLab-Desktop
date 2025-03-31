#include "mainwindow.h"

#include <QApplication>
#include <signal.h>

#include "proxy_service.h"
#include "tracy/Tracy.hpp"


int main(int argc, char *argv[]) {
#ifdef _POSIX
	signal(SIGPIPE, SIG_IGN);
#endif
	TracyNoop;
	std::shared_ptr<ProxyService> proxyService = std::make_shared<ProxyService>();
	QApplication a(argc, argv);
	MainWindow w(proxyService);
	w.show();

	return a.exec();
}
