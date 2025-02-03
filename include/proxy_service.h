#pragma once

#include <memory>
#include <thread>
#include <list>
#include <pcapplusplus/PcapFileDevice.h>

#include "client.h"
#include "connection_manager.h"

class ProxyService {
	std::list<std::shared_ptr<Client>> clients;
	std::thread thread;
	SOCKET serverSocket;
	SOCKET serverSocket6;
	std::atomic_bool stopFlag = false;
	std::shared_ptr<ConnectionManager> connections;
	std::shared_ptr<pcpp::PcapFileWriterDevice> pcapWriter;
	ndpi::ndpi_detection_module_struct *ndpiStruct;
	std::shared_ptr<DnsManager> dnsManager;

	public:
		ProxyService();
		~ProxyService();

		void start();
		void stop();

		[[nodiscard]] std::shared_ptr<ConnectionManager> getConnections() const {
			return connections;
		}

		[[nodiscard]] std::shared_ptr<DnsManager> getDnsManager() const {
			return dnsManager;
		}

		[[nodiscard]] std::shared_ptr<pcpp::PcapFileWriterDevice> getPcapWriter() const {
			return pcapWriter;
		}

		[[nodiscard]] ndpi::ndpi_detection_module_struct *getNdpiStruct() const {
			return ndpiStruct;
		}

	protected:
		void threadRoutine();
		void acceptClient4();
		void acceptClient6();
		void packetLoop();
		void sendFromDevice(std::shared_ptr<Client> client);
		void cleanUpAfterClient(std::shared_ptr<Client> client);
};
