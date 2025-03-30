#pragma once

#include <functional>
#include <memory>
#include <set>
#include <unordered_map>

#include <boost/signals2.hpp>
#include <pcapplusplus/IpAddress.h>

#include "protocol.h"

class Connection;
class TcpConnection;

class ConnectionManager {
	protected:
		unsigned long long orderNum = 0;
		int maxConnections = 1000;
		std::unordered_map<std::string, std::shared_ptr<Connection>> connections{};
		std::set<std::shared_ptr<TcpConnection>> tlsConnections{};
		boost::signals2::signal<void (bool, std::shared_ptr<Connection>)> connectionAddedSignal;
		boost::signals2::signal<void (bool, std::shared_ptr<TcpConnection>)> tlsConnectionAddedSignal;

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

		[[nodiscard]] boost::signals2::signal<void(bool, std::shared_ptr<Connection>)>& getConnectionAddedSignal() {
			return connectionAddedSignal;
		}

		[[nodiscard]] boost::signals2::signal<void(bool, std::shared_ptr<TcpConnection>)>& getTlsConnectionAddedSignal() {
			return tlsConnectionAddedSignal;
		}

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
