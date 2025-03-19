#pragma once

#include <functional>
#include <memory>
#include <set>
#include <unordered_map>
#include <pcapplusplus/IpAddress.h>

#include "protocol.h"

class Connection;
class TcpConnection;

class ConnectionManager {
	public:
		using OnConnectionCallback = std::shared_ptr<std::function<void (bool, std::shared_ptr<Connection>)>>;
		using OnTlsConnectionCallback = std::shared_ptr<std::function<void (bool, std::shared_ptr<TcpConnection>)>>;

	protected:
		unsigned long long orderNum = 0;
		int maxConnections = 1000;
		std::unordered_map<std::string, std::shared_ptr<Connection>> connections{};
		std::set<std::shared_ptr<TcpConnection>> tlsConnections{};
		std::set<OnConnectionCallback> onConnectionCallbacks{};
		std::set<OnTlsConnectionCallback> onTlsConnectionCallbacks{};

	public:
		void addConnection(const std::shared_ptr<Connection>& connection);

		std::shared_ptr<Connection> find(
			const pcpp::IPAddress &clientIp,
			const pcpp::IPAddress& srcIp,
			const pcpp::IPAddress& dstIp,
			uint16_t srcPort,
			uint16_t dstPort,
			Protocol protocol
		);

		[[nodiscard]] std::unordered_map<std::string, std::shared_ptr<Connection>>& getConnections();

		void registerConnectionCallback(const OnConnectionCallback &callback);
		void unregisterConnectionCallback(OnConnectionCallback callback);
		void registerTlsConnectionCallback(const OnTlsConnectionCallback &callback);
		void unregisterTlsConnectionCallback(OnTlsConnectionCallback callback);
		void markAsTlsConnection(std::shared_ptr<TcpConnection> connection);

	protected:
		static std::string getKey(
			const pcpp::IPAddress &clientIp,
			const pcpp::IPAddress& srcIp,
			const pcpp::IPAddress& dstIp,
			uint16_t srcPort,
			uint16_t dstPort,
			Protocol protocol
		);

		void cleanUp();
};
