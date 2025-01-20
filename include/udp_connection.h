#pragma once

#include <vector>

#include "connection.h"

class UdpConnection : public Connection {
	public:
		UdpConnection(
			pcpp::IPAddress originHostIp,
			uint16_t originHostPort,
			pcpp::IPAddress src_ip,
			pcpp::IPAddress dst_ip,
			uint16_t src_port,
			uint16_t dst_port,
			SOCKET deviceSocket,
			ndpi::ndpi_detection_module_struct *ndpiStruct
		);

		~UdpConnection() override;

		void processPacketFromDevice(pcpp::IPv4Layer *ipv4Layer) override;

		void openSocket();

		void sendDataToRemote(const std::vector<uint8_t> &data) override;

		void close();

		std::vector<uint8_t> read() override;

		std::unique_ptr<pcpp::Packet> encapsulateResponseDataToPacket(const std::vector<uint8_t> &data) override;

		void sendDataToDeviceSocket(const std::vector<uint8_t> &data) override;
};
