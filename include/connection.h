#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>

#include "sockets.h"
#include "client.h"
#include "protocol.h"
#include "remote_socket_status.h"
#include "ndpi.h"

class DnsManager;

namespace pcpp {
	class IPv4Layer;
}

class Connection : public std::enable_shared_from_this<Connection> {
	public:
		static constexpr unsigned int DEFAULT_MAX_SEGMENT_SIZE = 1400;

		enum class IpVersion {
			IPV4,
			IPV6
		};

	protected:
		unsigned long long orderNum{};
		pcpp::IPAddress srcIp;
		pcpp::IPAddress dstIp;
		uint16_t srcPort{};
		uint16_t dstPort{};
		std::atomic<RemoteSocketStatus> remoteSocketStatus = RemoteSocketStatus::CLOSED;
		std::chrono::system_clock::time_point createdTime = std::chrono::system_clock::now();
		std::optional<std::chrono::system_clock::time_point> lastPacketSentTime;
		Protocol protocol;
		SOCKET socket{};
		std::deque<uint8_t> dataStream{};
		sockaddr_in originSockAddr{};
		unsigned int maxSegmentSize = DEFAULT_MAX_SEGMENT_SIZE;

		std::shared_mutex mutex{};

		std::atomic_uint64_t sentPacketCount = 0;
		std::atomic_uint64_t receivedPacketCount = 0;
		std::atomic_uint64_t sentBytes = 0;
		std::atomic_uint64_t receivedBytes = 0;

		ndpi::ndpi_detection_module_struct *ndpiStr = nullptr;
		std::unique_ptr<ndpi::ndpi_flow_struct, std::function<void(ndpi::ndpi_flow_struct *)>> ndpiFlow = nullptr;
		ndpi::ndpi_protocol ndpiProtocol{};
		std::shared_ptr<pcpp::PcapNgFileWriterDevice> pcapWriter;
		std::shared_ptr<DnsManager> dnsManager;
		std::shared_ptr<Client> client;

	public:
		Connection(
			std::shared_ptr<Client> client,
			pcpp::IPAddress src_ip,
			pcpp::IPAddress dst_ip,
			uint16_t src_port,
			uint16_t dst_port,
			Protocol protocol,
			ndpi::ndpi_detection_module_struct *ndpiStruct
		);

		virtual ~Connection() = default;

		virtual void processPacketFromDevice(pcpp::Layer *networkLayer) = 0;

		virtual void sendDataToRemote(std::span<const uint8_t> data) = 0;

		virtual std::vector<uint8_t> read() = 0;

		virtual void writeEvent() {}

		virtual void exceptionEvent() {}

		virtual std::unique_ptr<pcpp::Packet> encapsulateResponseDataToPacket(std::span<const uint8_t> data) = 0;

		virtual void sendDataToDeviceSocket(std::span<const uint8_t> data) = 0;

		virtual void sendToDeviceSocket(const pcpp::Packet &packet);

		void processDpi(const unsigned char *packetPtr, unsigned short packetLen);

		[[nodiscard]] virtual bool canRemove() const = 0;

		virtual void gracefullyCloseRemoteSocket() = 0;

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

		[[nodiscard]] const std::deque<uint8_t> &getDataStream() const;

		[[nodiscard]] const sockaddr_in& getDestSockAddr() const;

		[[nodiscard]] ndpi::ndpi_protocol getNdpiProtocol() const;

		void setPcapWriter(const std::shared_ptr<pcpp::PcapNgFileWriterDevice> &pcapWriter);

		void setDnsManager(std::shared_ptr<DnsManager> dnsManager);

		[[nodiscard]] std::unique_ptr<ndpi::ndpi_flow_struct, std::function<void(ndpi::ndpi_flow_struct *)>>& getNdpiFlow();

		void log(const std::string& msg) const;

		bool isIpv6() const;

		[[nodiscard]] virtual std::unique_ptr<pcpp::Layer> buildIpLayer();

		[[nodiscard]] std::shared_ptr<Client> getClient() const;

		virtual void forcefullyCloseAll() = 0;

		[[nodiscard]] unsigned long long getOrderNum() const;

		void setOrderNum(unsigned long long order_num);

		void closeSocketAndInvalidate();

		[[nodiscard]] std::atomic_uint64_t getSentPacketCount() const;

		[[nodiscard]] std::atomic_uint64_t getReceivedPacketCount() const;

		[[nodiscard]] std::atomic_uint64_t getSentBytes() const;

		[[nodiscard]] std::atomic_uint64_t getReceivedBytes() const;
};
