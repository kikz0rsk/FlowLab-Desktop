#pragma once

#include <pcapplusplus/IpAddress.h>
#include <winsock2.h>

class Client {
	SOCKET clientSocket;
	pcpp::IPAddress clientIp;
	uint16_t port;

	public:
		Client(SOCKET clientSocket, pcpp::IPAddress clientIp, uint16_t port) : clientSocket(clientSocket), clientIp(clientIp), port(port) {}
		~Client() = default;

		[[nodiscard]] SOCKET getClientSocket() const {
			return clientSocket;
		}

		[[nodiscard]] const pcpp::IPAddress & getClientIp() const {
			return clientIp;
		}
};
