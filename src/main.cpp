#include <client_forwarder.h>

#include "mainwindow.h"

#include <QApplication>

#include "proxy_service.h"
#include "tracy/Tracy.hpp"

int main(int argc, char *argv[]) {
	TracyNoop;
	// ClientForwarder clientForwarder(
	// 	[](uint64_t seq_no, std::span<const uint8_t> data) {
	// 		ZoneScoped;
	// 		Logger::get().log("Received " + std::to_string(data.size()) + " data bytes from server");
	// 	},
	// 	[](std::span<const uint8_t> data) {
	// 		ZoneScoped;
	// 		Logger::get().log("Queueing " + std::to_string(data.size()) + " TLS bytes to server");
	// 	},
	// 	ClientForwarder::TlsAlertCallback([](Botan::TLS::Alert alert) {
	// 		ZoneScoped;
	// 		Logger::get().log("TLS alert: " + alert.type_string());
	// 	}),
	// 	[](const Botan::X509_Certificate &cert) {
	// 		ZoneScoped;
	// 		Logger::get().log("Received certificate: " + cert.to_string());
	// 	}
	// );
	//
	// return 0;

	std::shared_ptr<ProxyService> proxyService = std::make_shared<ProxyService>();
	QApplication a(argc, argv);
	MainWindow w(proxyService);
	w.show();
	proxyService->start();

	return a.exec();
}
