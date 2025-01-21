#pragma once

#include <atomic>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <pcapplusplus/IpAddress.h>
#include <winsock2.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>

#include "dns_manager.h"
#include "logger.h"
#include "protocol.h"
#include "remote_socket_status.h"
#include "ndpi.h"

namespace pcpp {
	class IPv4Layer;
}

class Connection {
	public:
		static constexpr unsigned int MAX_SEGMENT_SIZE = 1430;

	protected:
		pcpp::IPAddress originHostIp;
		std::string originHostIpStr;
		uint16_t originHostPort;

		pcpp::IPAddress srcIp;
		pcpp::IPAddress dstIp;
		uint16_t srcPort{};
		uint16_t dstPort{};
		std::atomic<RemoteSocketStatus> remoteSocketStatus = RemoteSocketStatus::CLOSED;
		std::chrono::system_clock::time_point createdTime = std::chrono::system_clock::now();
		std::optional<std::chrono::system_clock::time_point> lastPacketSentTime;
		Protocol protocol;
		SOCKET socket{};
		SOCKET deviceSocket{};
		std::vector<uint8_t> dataStream{};
		sockaddr_in originSockAddr{};

		std::shared_mutex mutex{};

		int sentPacketCount = 0;
		int receivedPacketCount = 0;

		ndpi::ndpi_detection_module_struct *ndpiStr = nullptr;
		ndpi::ndpi_flow_struct *ndpiFlow = nullptr;
		ndpi::ndpi_protocol ndpiProtocol{};
		std::shared_ptr<pcpp::PcapFileWriterDevice> pcapWriter;
		DnsManager* dnsManager;

	public:
		Connection(
			pcpp::IPAddress originHostIp,
			uint16_t originHostPort,
			pcpp::IPAddress src_ip,
			pcpp::IPAddress dst_ip,
			uint16_t src_port,
			uint16_t dst_port,
			Protocol protocol,
			SOCKET deviceSocket,
			ndpi::ndpi_detection_module_struct *ndpiStruct
		);

		virtual ~Connection();

		virtual void processPacketFromDevice(pcpp::IPv4Layer *ipv4Layer) = 0;

		virtual void sendDataToRemote(const std::vector<uint8_t> &data) = 0;

		virtual std::vector<uint8_t> read() = 0;

		virtual void writeEvent() {}

		virtual void exceptionEvent() {}

		virtual std::unique_ptr<pcpp::Packet> encapsulateResponseDataToPacket(const std::vector<uint8_t> &data) = 0;

		virtual void sendDataToDeviceSocket(const std::vector<uint8_t> &data) = 0;

		virtual void sendToDeviceSocket(const pcpp::Packet &packet);

		void processDpi(const unsigned char *packetPtr, unsigned short packetLen);

		[[nodiscard]] virtual bool shouldClose() const;

		[[nodiscard]] std::shared_lock<std::shared_mutex> getReadLock();

		[[nodiscard]] std::unique_lock<std::shared_mutex> getWriteLock();

		[[nodiscard]] const Protocol &getProtocol() const;

		[[nodiscard]] const std::chrono::system_clock::time_point &getCreatedTime() const;

		[[nodiscard]] const std::optional<std::chrono::system_clock::time_point> &getLastPacketSentTime() const;

		[[nodiscard]] const pcpp::IPAddress &getSrcIp() const;

		void setSrcIp(const pcpp::IPAddress &srcIp);

		[[nodiscard]] const pcpp::IPAddress &getDstIp() const;

		void setDstIp(const pcpp::IPAddress &dstIp);

		[[nodiscard]] uint16_t getSrcPort() const;

		void setSrcPort(uint16_t srcPort);

		[[nodiscard]] uint16_t getDstPort() const;

		void setDstPort(uint16_t dstPort);

		[[nodiscard]] RemoteSocketStatus getRemoteSocketStatus() const;

		void setRemoteSocketStatus(RemoteSocketStatus status);

		[[nodiscard]] SOCKET getSocket() const;

		[[nodiscard]] const std::vector<uint8_t> &getDataStream() const;

		[[nodiscard]] const pcpp::IPAddress &getOriginHostIp() const;

		[[nodiscard]] uint16_t getOriginHostPort() const;

		[[nodiscard]] const sockaddr_in& getDestSockAddr() const;

		[[nodiscard]] ndpi::ndpi_protocol getNdpiProtocol() const;

		void setPcapWriter(const std::shared_ptr<pcpp::PcapFileWriterDevice> &pcapWriter);

		void setDnsManager(DnsManager *dnsManager);
};
