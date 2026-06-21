#pragma once

#include <queue>
#include <vector>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/SystemUtils.h>
#include <botan/tls_server.h>

class ProxyService;
class UdpConnection;
class TcpConnection;
class ConnectionManager;

class Client : public std::enable_shared_from_this<Client> {
	std::shared_ptr<ProxyService> proxyService;
	std::shared_ptr<ConnectionManager> connectionManager;
	boost::asio::ip::tcp::socket clientSocket;
	pcpp::IPAddress clientIp;
	uint16_t port;
	std::queue<std::vector<uint8_t>> unencryptedQueueToDevice;
	std::vector<uint8_t> unencryptedQueueFromDevice;
	std::vector<uint8_t> encryptedQueueToDevice;
	std::shared_ptr<Botan::TLS::Server> tlsConnection;
	bool outgoingDrainActive = false;

	public:
		Client(
			boost::asio::ip::tcp::socket clientSocket,
			pcpp::IPAddress clientIp,
			uint16_t port
		);

		~Client();

		void handleClient();

		boost::asio::awaitable<void> decryptIncomingCoroutine();

		bool processIncomingData();

		boost::asio::awaitable<void> encryptOutgoingCoroutine();

		void sendRst(pcpp::IPAddress srcIp, pcpp::IPAddress dstIp, uint16_t srcPort, uint16_t dstPort, bool isIpv6, uint32_t sequenceNumber = 0);

		[[nodiscard]] const boost::asio::ip::tcp::socket& getClientSocket() const;

		[[nodiscard]] const pcpp::IPAddress & getClientIp() const;

		[[nodiscard]] std::queue<std::vector<uint8_t>>& getUnencryptedQueueToDevice();

		void setTlsServer(std::shared_ptr<Botan::TLS::Server> tlsServer);

		[[nodiscard]] std::shared_ptr<Botan::TLS::Server> getTlsConnection();

		void enqueueData(std::vector<uint8_t> data);

		[[nodiscard]] std::vector<uint8_t> & getUnencryptedQueueFromDevice();

		[[nodiscard]] std::vector<uint8_t> & getEncryptedQueueToDevice();
};
