#pragma once

#include <QStandardItemModel>
#include <regex>
#include <thread>

#include "client.h"
#include "connection.h"
#include "processor_context.h"
#include "tcp_state.h"
#include "tcp_status.h"

class IProcessor;

namespace pcpp {
	class TcpLayer;
}

class ProxyService;
class ServerForwarder;
class ClientForwarder;

class TcpConnection : public Connection {
	protected:
		static constexpr const char *SERVER_TAG = "SERVER>>>>>>>>>";
		static constexpr const char *CLIENT_TAG = "CLIENT>>>>>>>>>";
		static constexpr int MAX_DATA_STREAM_SIZE = 1'000'000;

		bool doTlsRelay = false;

		boost::asio::ip::tcp::socket destSocket;
		TcpState tcpState{};
		TcpStatus tcpStatus = TcpStatus::CLOSED;

		std::atomic_bool remoteWriteInProgress = false;
		std::mutex remoteWriteMutex;
		std::deque<std::vector<uint8_t>> remoteWriteQueue;

	public:
		TcpConnection(
			std::shared_ptr<ProxyService> proxyService,
			std::shared_ptr<Client> client,
			const pcpp::IPAddress& src_ip,
			const pcpp::IPAddress& dst_ip,
			uint16_t src_port,
			uint16_t dst_port,
			ndpi::ndpi_detection_module_struct *ndpiStruct
		);

		~TcpConnection() override;

		boost::asio::awaitable<void> processPacketFromDevice(pcpp::Layer *networkLayer) override;

	private:

		void resetState();

		void closeSocketSoft() override;

		void sendFinAck();

		void sendSynAck();

		boost::asio::awaitable<void> openSocket();

		void sendAck();

		boost::asio::awaitable<void> sendDataToRemote(std::span<const uint8_t> data) override;

		boost::asio::awaitable<void> read() override;

		boost::asio::awaitable<void> readLoop();

		std::unique_ptr<pcpp::Packet> encapsulateResponseDataToPacket(std::span<const uint8_t> data) override;

		void sendDataToDevice(std::span<const uint8_t> data) override;

		void sendRst(bool ack = false);

		[[nodiscard]] TcpStatus getTcpStatus() const;

		void setTcpStatus(TcpStatus tcpStatus);

		void closeAllForce() override;

		[[nodiscard]] bool canRemove() const override;

		void logToFile() override;

		std::unique_ptr<pcpp::TcpLayer> buildTcpLayer() const;
};
