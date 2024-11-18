#pragma once
#include <memory>
#include <unordered_map>

#include "connection.h"

class ConnectionManager {
	protected:
		int maxConnections = 1000;
		std::unordered_map<std::string, std::shared_ptr<Connection>> connections;

	public:
		void addConnection(const std::shared_ptr<Connection>& connection) {
			connections[getKey(connection->getSrcIp(), connection->getDstIp(), connection->getSrcPort(), connection->getDstPort(), connection->getProtocol())] = connection;
		}

		std::shared_ptr<Connection> find(const pcpp::IPAddress& src_ip, const pcpp::IPAddress& dst_ip, uint16_t src_port, uint16_t dst_port, Protocol protocol) {
			auto key = getKey(src_ip, dst_ip, src_port, dst_port, protocol);
			auto connectionEntry = connections.find(key);
			if (connectionEntry == connections.end()) {
				return {};
			}

			return connectionEntry->second;
		}

		[[nodiscard]] std::unordered_map<std::string, std::shared_ptr<Connection>>& getConnections() {
			return connections;
		}

	protected:
		static std::string getKey(const pcpp::IPAddress& src_ip, const pcpp::IPAddress& dst_ip, uint16_t src_port, uint16_t dst_port, Protocol protocol) {
			return src_ip.toString() + "," + std::to_string(src_port) + "," + dst_ip.toString() + "," + std::to_string(dst_port) + "," + (protocol == Protocol::TCP ? "tcp" : "udp");
		}
};
