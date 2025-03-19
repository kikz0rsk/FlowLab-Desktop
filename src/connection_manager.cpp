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
	for (const auto &callback : onConnectionCallbacks) {
		callback->operator()(true, connection);
	}
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
		for (const auto &callback : onConnectionCallbacks) {
			callback->operator()(false, it->second);
		}
		if (tcpCon && tlsConnections.contains(tcpCon)) {
			for (const auto &callback : onTlsConnectionCallbacks) {
				callback->operator()(false, tcpCon);
			}
			tlsConnections.erase(tcpCon);
		}
		it = connections.erase(it);
	}
}

void ConnectionManager::registerConnectionCallback(const OnConnectionCallback &callback) {
	onConnectionCallbacks.emplace(callback);
}

void ConnectionManager::unregisterConnectionCallback(OnConnectionCallback callback) {
	onConnectionCallbacks.erase(callback);
}

void ConnectionManager::registerTlsConnectionCallback(const OnTlsConnectionCallback &callback) {
	onTlsConnectionCallbacks.emplace(callback);
}

void ConnectionManager::unregisterTlsConnectionCallback(OnTlsConnectionCallback callback) {
	onTlsConnectionCallbacks.erase(callback);
}

void ConnectionManager::markAsTlsConnection(std::shared_ptr<TcpConnection> connection) {
	tlsConnections.insert(connection);
	for (const auto &callback : onTlsConnectionCallbacks) {
		callback->operator()(true, connection);
	}
}
