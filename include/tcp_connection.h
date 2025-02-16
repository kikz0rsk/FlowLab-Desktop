#pragma once

#include <thread>

#include "client.h"
#include "connection.h"
#include "tcp_status.h"

class TcpConnection : public Connection {
	protected:
		unsigned int ackNumber{};
		std::atomic_uint32_t ourSequenceNumber = 0;
		unsigned long long ourWindowSize = 65'535;
		unsigned long long remoteWindowSize = 65'535;
		uint32_t finSequenceNumber = 0;
		unsigned long long unAckedBytes = 0;
		unsigned int lastRemoteAckedNum = 0;
		unsigned int windowSizeMultiplier = 1;
		bool shouldSendFinOnAckedEverything = false;
		std::atomic<TcpStatus> tcpStatus = TcpStatus::CLOSED;
		std::shared_ptr<Forwarder> forwarder;

	public:
		TcpConnection(
			std::shared_ptr<Client> client,
			const pcpp::IPAddress &src_ip,
			const pcpp::IPAddress &dst_ip,
			uint16_t src_port,
			uint16_t dst_port,
			ndpi::ndpi_detection_module_struct *ndpiStruct
		);

		~TcpConnection() override;

		void resetState();

		void gracefullyCloseRemoteSocket() override;

		void sendFinAck();

		void sendSynAck();

		void processPacketFromDevice(pcpp::Layer *networkLayer) override;

		void openSocket();

		void sendAck();

		void sendDataToRemote(std::span<const uint8_t> data) override;

		std::vector<uint8_t> read() override;

		void writeEvent() override;

		void exceptionEvent() override;

		std::unique_ptr<pcpp::Packet> encapsulateResponseDataToPacket(std::span<const uint8_t> data) override;

		void sendDataToDeviceSocket(std::span<const uint8_t> data) override;

		[[nodiscard]] unsigned int getAckNumber() const;

		[[nodiscard]] std::atomic_uint32_t &getOurSequenceNumber();

		void sendRst();

		[[nodiscard]]  static unsigned long getBytesAvailable(SOCKET socket);

		[[nodiscard]] TcpStatus getTcpStatus() const;

		void setTcpStatus(TcpStatus tcpStatus);

		void forcefullyCloseAll() override;
};
