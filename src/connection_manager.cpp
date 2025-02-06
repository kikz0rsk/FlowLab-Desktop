#include "connection_manager.h"

void ConnectionManager::addConnection(const std::shared_ptr<Connection> &connection) {
	connections[
		getKey(
			connection->getClient()->getClientIp(),
			connection->getSrcIp(),
			connection->getDstIp(),
			connection->getSrcPort(),
			connection->getDstPort(),
			connection->getProtocol()
		)
	] = connection;
	connection->setOrderNum(orderNum++);
}

std::shared_ptr<Connection> ConnectionManager::find(
	const pcpp::IPAddress &clientIp,
	const pcpp::IPAddress &srcIp,
	const pcpp::IPAddress &dstIp,
	uint16_t srcPort,
	uint16_t dstPort,
	Protocol protocol
) {
	auto key = getKey(clientIp, srcIp, dstIp, srcPort, dstPort, protocol);
	auto connectionEntry = connections.find(key);
	if (connectionEntry == connections.end()) {
		return {};
	}

	return connectionEntry->second;
}

std::unordered_map<std::string, std::shared_ptr<Connection>> & ConnectionManager::getConnections() {
	return connections;
}

std::string ConnectionManager::getKey(
	const pcpp::IPAddress &clientIp,
	const pcpp::IPAddress &srcIp,
	const pcpp::IPAddress &dstIp,
	uint16_t srcPort,
	uint16_t dstPort,
	Protocol protocol
) {
	return clientIp.toString() + "," + srcIp.toString() + "," + std::to_string(srcPort) + "," + dstIp.toString() + "," + std::to_string(dstPort) + "," + (protocol ==
		Protocol::TCP ? "tcp" : "udp");
}
