#include "connection_manager.h"

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
		if (it->second->canRemove()) {
			for (const auto &callback : onConnectionCallbacks) {
				callback->operator()(false, it->second);
			}
			it = connections.erase(it);
		} else {
			++it;
		}
	}
}

void ConnectionManager::registerConnectionCallback(const OnConnectionCallback &callback) {
	onConnectionCallbacks.emplace(callback);
}

void ConnectionManager::unregisterConnectionCallback(OnConnectionCallback callback) {
	for (auto it = onConnectionCallbacks.begin(); it != onConnectionCallbacks.end(); ++it) {
		if (*it == callback) {
			onConnectionCallbacks.erase(it);
			break;
		}
	}
}
