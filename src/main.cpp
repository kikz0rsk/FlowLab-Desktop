#include <client_forwarder.h>

#include "mainwindow.h"

#include <QApplication>

#include "proxy_service.h"
#include "tracy/Tracy.hpp"

int main(int argc, char *argv[]) {
	TracyNoop;
	std::shared_ptr<ProxyService> proxyService = std::make_shared<ProxyService>();
	QApplication a(argc, argv);
	MainWindow w(proxyService);
	w.show();
	proxyService->start();

	return a.exec();
}
