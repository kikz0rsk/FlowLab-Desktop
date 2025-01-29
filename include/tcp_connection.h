#pragma once

#include <thread>

#include "connection.h"
#include "tcp_status.h"

class TcpConnection : public Connection {
	protected:
		unsigned int ackNumber{};
		std::atomic_uint32_t ourSequenceNumber = 0;
		unsigned short ourWindowSize = 65'535;
		unsigned short remoteWindowSize = 65'535;
		std::thread connectingThread;
		uint32_t finSequenceNumber = 0;
		unsigned int unAckedBytes = 0;
		unsigned int lastRemoteAckedNum = 0;
		unsigned int windowSizeMultiplier = 1;
		bool shouldSendFinOnAckedEverything = false;
		std::atomic<TcpStatus> tcpStatus = TcpStatus::CLOSED;
		std::shared_ptr<Forwarder> forwarder;

	public:
		TcpConnection(
			pcpp::IPAddress originHostIp,
			uint16_t originHostPort,
			const pcpp::IPAddress &src_ip,
			const pcpp::IPAddress &dst_ip,
			uint16_t src_port,
			uint16_t dst_port,
			SOCKET deviceSocket,
			ndpi::ndpi_detection_module_struct *ndpiStruct
		);

		~TcpConnection() override;

		void resetState();

		void closeRemoteSocket();

		void sendFinAck();

		void sendSynAck();

		void processPacketFromDevice(pcpp::IPv4Layer *ipv4Layer) override;

		void openSocket();

		void sendAck();

		void sendDataToRemote(std::vector<uint8_t> &data) override;

		std::vector<uint8_t> read() override;

		void writeEvent() override;

		void exceptionEvent() override;

		std::unique_ptr<pcpp::Packet> encapsulateResponseDataToPacket(const std::vector<uint8_t> &data) override;

		void sendDataToDeviceSocket(const std::vector<uint8_t> &data) override;

		[[nodiscard]] unsigned int getAckNumber() const;

		[[nodiscard]] std::atomic_uint32_t &getOurSequenceNumber();

		void sendRst();

		[[nodiscard]]  static unsigned long getBytesAvailable(SOCKET socket);

		[[nodiscard]] TcpStatus getTcpStatus() const;

		void setTcpStatus(TcpStatus tcpStatus);
};
