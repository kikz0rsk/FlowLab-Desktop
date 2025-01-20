#pragma once

#include <memory>
#include <unordered_map>

#include "connection.h"

class ConnectionManager {
	protected:
		int maxConnections = 1000;
		std::unordered_map<std::string, std::shared_ptr<Connection>> connections;

	public:
		void addConnection(const std::shared_ptr<Connection>& connection);

		std::shared_ptr<Connection> find(const pcpp::IPAddress& src_ip, const pcpp::IPAddress& dst_ip, uint16_t src_port, uint16_t dst_port, Protocol protocol);

		[[nodiscard]] std::unordered_map<std::string, std::shared_ptr<Connection>>& getConnections();

	protected:
		static std::string getKey(const pcpp::IPAddress& src_ip, const pcpp::IPAddress& dst_ip, uint16_t src_port, uint16_t dst_port, Protocol protocol);
};
