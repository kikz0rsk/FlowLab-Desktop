#include "connection_manager.h"

#include "tcp_connection.h"

void ConnectionManager::addConnection(const std::shared_ptr<Connection> &connection) {
	if (connections.size() > 3000) {
		cleanUp();
	}
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
	this->connectionAddedSignal(true, connection);
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

void ConnectionManager::cleanUp() {
	for (auto it = connections.begin(); it != connections.end();) {
		if (!it->second->canRemove()) {
			++it;
			continue;
		}

		auto tcpCon = std::dynamic_pointer_cast<TcpConnection>(it->second);
		this->connectionAddedSignal(false, it->second);
		if (tcpCon && tlsConnections.contains(tcpCon)) {
			this->tlsConnectionAddedSignal(false, tcpCon);
			tlsConnections.erase(tcpCon);
		}
		it = connections.erase(it);
	}
}

void ConnectionManager::markAsTlsConnection(std::shared_ptr<TcpConnection> connection) {
	tlsConnections.insert(connection);
	this->tlsConnectionAddedSignal(true, connection);
}
