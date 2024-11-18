#pragma once

#include <mutex>
#include <shared_mutex>
#include <pcapplusplus/IpAddress.h>
#include <winsock2.h>
#include <pcapplusplus/Packet.h>

#include "protocol.h"
#include "remote_socket_status.h"
#include "tcp_status.h"
#include "ndpi.h"

namespace pcpp {
	class IPv4Layer;
}

class Connection {
protected:
	pcpp::IPAddress originHostIp;
	std::string originHostIpStr;
	uint16_t originHostPort;

	pcpp::IPAddress srcIp;
	pcpp::IPAddress dstIp;
	uint16_t srcPort{};
	uint16_t dstPort{};
	std::atomic<RemoteSocketStatus> remoteSocketStatus = RemoteSocketStatus::CLOSED;
	std::atomic<TcpStatus> tcpStatus = TcpStatus::CLOSED;
	std::chrono::system_clock::time_point createdTime = std::chrono::system_clock::now();
	std::optional<std::chrono::system_clock::time_point> lastPacketSentTime;
	Protocol protocol;
	SOCKET socket{};
	std::vector<uint8_t> dataStream{};
	sockaddr_in originSockAddr{};

	std::shared_mutex mutex{};
	ndpi::ndpi_detection_module_struct *ndpiStruct = nullptr;

public:
	Connection(pcpp::IPAddress originHostIp, uint16_t originHostPort, pcpp::IPAddress src_ip, pcpp::IPAddress dst_ip, uint16_t src_port, uint16_t dst_port, Protocol protocol)
		: originHostIp(originHostIp),
		  originHostPort(originHostPort),
		  srcIp(src_ip),
		  dstIp(dst_ip),
		  srcPort(src_port),
		  dstPort(dst_port),
		  protocol(protocol),
		  originHostIpStr(originHostIp.toString()) {
		dataStream.reserve(5'000);
		originSockAddr = sockaddr_in{AF_INET, htons(originHostPort)};
		originSockAddr.sin_addr.s_addr = inet_addr(originHostIpStr.c_str());

		ndpiStruct = ndpi::ndpi_init_detection_module(nullptr);
		if (ndpiStruct == nullptr) {
			throw std::runtime_error("Failed to initialize nDPI");
		}

		ndpi::ndpi_protocol_bitmask_struct_t all;
		NDPI_BITMASK_SET_ALL(all);
		ndpi::ndpi_set_protocol_detection_bitmask2(ndpiStruct, &all);
		ndpi::ndpi_finalize_initialization(ndpiStruct);
	}

	virtual ~Connection() {
		ndpi::ndpi_exit_detection_module(ndpiStruct);
	}

	virtual void processPacketFromDevice(pcpp::IPv4Layer *ipv4Layer) = 0;

	virtual void sendDataToRemote(const std::vector<uint8_t> &data) = 0;

	virtual std::vector<uint8_t> read() = 0;

	virtual std::unique_ptr<pcpp::Packet> encapsulateResponseDataToPacket(const std::vector<uint8_t> &data) = 0;

	[[nodiscard]] virtual bool shouldClose() const {
		if (lastPacketSentTime.has_value()) {
			return std::chrono::system_clock::now() - *lastPacketSentTime > std::chrono::seconds(30);
		} else {
			return std::chrono::system_clock::now() - createdTime > std::chrono::seconds(30);
		}
	}

	[[nodiscard]] std::shared_lock<std::shared_mutex> getReadLock() {
		return std::shared_lock(mutex);
	}

	[[nodiscard]] std::unique_lock<std::shared_mutex> getWriteLock() {
		return std::unique_lock(mutex);
	}

	[[nodiscard]] const Protocol &getProtocol() const {
		return protocol;
	}

	[[nodiscard]] const std::chrono::system_clock::time_point &getCreatedTime() const {
		return createdTime;
	}

	[[nodiscard]] const std::optional<std::chrono::system_clock::time_point> &getLastPacketSentTime() const {
		return lastPacketSentTime;
	}

	[[nodiscard]] const pcpp::IPAddress &getSrcIp() const {
		return srcIp;
	}

	void setSrcIp(const pcpp::IPAddress &srcIp) {
		Connection::srcIp = srcIp;
	}

	[[nodiscard]] const pcpp::IPAddress &getDstIp() const {
		return dstIp;
	}

	void setDstIp(const pcpp::IPAddress &dstIp) {
		Connection::dstIp = dstIp;
	}

	[[nodiscard]] uint16_t getSrcPort() const {
		return srcPort;
	}

	void setSrcPort(uint16_t srcPort) {
		Connection::srcPort = srcPort;
	}

	[[nodiscard]] uint16_t getDstPort() const {
		return dstPort;
	}

	void setDstPort(uint16_t dstPort) {
		Connection::dstPort = dstPort;
	}

	[[nodiscard]] RemoteSocketStatus getRemoteSocketStatus() const {
		return remoteSocketStatus;
	}

	void setRemoteSocketStatus(RemoteSocketStatus status) {
		remoteSocketStatus = status;
	}

	[[nodiscard]] TcpStatus getTcpStatus() const {
		return tcpStatus;
	}

	void setTcpStatus(TcpStatus tcpStatus) {
		Connection::tcpStatus = tcpStatus;
	}

	[[nodiscard]] SOCKET getSocket() const {
		return socket;
	}

	[[nodiscard]] const std::vector<uint8_t> &getDataStream() const {
		return dataStream;
	}

	[[nodiscard]] const pcpp::IPAddress &getOriginHostIp() const {
		return originHostIp;
	}

	[[nodiscard]] uint16_t getOriginHostPort() const {
		return originHostPort;
	}

	[[nodiscard]] const sockaddr_in& getDestSockAddr() const {
		return originSockAddr;
	}
};
