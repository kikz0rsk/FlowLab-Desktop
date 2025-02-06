#pragma once

#include <deque>
#include <queue>
#include <utility>
#include <vector>
#include <pcapplusplus/IpAddress.h>
#include <winsock2.h>
#include <botan/tls_server.h>

#include "../build-release/vcpkg_installed/x64-mingw-static/include/botan/tls_channel.h"

class Client {
	SOCKET clientSocket;
	pcpp::IPAddress clientIp;
	uint16_t port;
	std::queue<std::vector<uint8_t>> unencryptedQueueToDevice;
	std::vector<uint8_t> unencryptedQueueFromDevice;
	std::vector<uint8_t> encryptedQueueToDevice;
	std::shared_ptr<Botan::TLS::Server> tlsServer;

	public:
		Client(SOCKET clientSocket, pcpp::IPAddress clientIp, uint16_t port) : clientSocket(clientSocket), clientIp(clientIp), port(port) {}
		~Client() = default;

		[[nodiscard]] SOCKET getClientSocket() const {
			return clientSocket;
		}

		[[nodiscard]] const pcpp::IPAddress & getClientIp() const {
			return clientIp;
		}

		[[nodiscard]] std::queue<std::vector<uint8_t>>& getUnencryptedQueueToDevice() {
			return unencryptedQueueToDevice;
		}

		void setTlsServer(std::shared_ptr<Botan::TLS::Server> tlsServer) {
			this->tlsServer = std::move(tlsServer);
		}

		[[nodiscard]] std::shared_ptr<Botan::TLS::Server> getTlsServer() {
			return tlsServer;
		}

		void enqueueData(std::vector<uint8_t> data) {
			unencryptedQueueToDevice.push(std::move(data));
		}

		[[nodiscard]] std::vector<uint8_t> & getUnencryptedQueueFromDevice() {
			return unencryptedQueueFromDevice;
		}

		[[nodiscard]] std::vector<uint8_t> & getEncryptedQueueToDevice() {
			return encryptedQueueToDevice;
		}
};
