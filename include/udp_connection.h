#pragma once

#include <vector>

#include "connection.h"

class UdpConnection : public Connection {
	public:
		UdpConnection(
			std::shared_ptr<Client> client,
			pcpp::IPAddress src_ip,
			pcpp::IPAddress dst_ip,
			uint16_t src_port,
			uint16_t dst_port,
			ndpi::ndpi_detection_module_struct *ndpiStruct
		);

		~UdpConnection() override;

		void processPacketFromDevice(pcpp::Layer *networkLayer) override;

		void openSocket();

		void sendDataToRemote(std::span<const uint8_t> data) override;

		void gracefullyCloseRemoteSocket() override;

		std::vector<uint8_t> read() override;

		std::unique_ptr<pcpp::Packet> encapsulateResponseDataToPacket(std::span<const uint8_t> data) override;

		void sendDataToDeviceSocket(std::span<const uint8_t> data) override;

		void forcefullyCloseAll() override;

		[[nodiscard]] bool canRemove() const override;
};
