#pragma once

#include <vector>
#include <boost/asio/ip/udp.hpp>

#include "connection.h"

class UdpConnection : public Connection {
	boost::asio::ip::udp::socket destSocket;

	public:
		static constexpr int BUFFER_SIZE = 4096;

		UdpConnection(
			std::shared_ptr<ProxyService> proxyService,
			std::shared_ptr<Client> client,
			pcpp::IPAddress src_ip,
			pcpp::IPAddress dst_ip,
			uint16_t src_port,
			uint16_t dst_port,
			ndpi::ndpi_detection_module_struct *ndpiStruct
		);

		~UdpConnection() override;

		boost::asio::awaitable<void> processPacketFromDevice(pcpp::Layer *networkLayer) override;

	private:
		boost::asio::awaitable<void> openSocket();

		boost::asio::awaitable<void> readLoop();

		boost::asio::awaitable<void> sendDataToRemote(std::span<const uint8_t> data) override;

		void gracefullyCloseRemoteSocket() override;

		boost::asio::awaitable<std::vector<uint8_t>> read() override;

		std::unique_ptr<pcpp::Packet> encapsulateResponseDataToPacket(std::span<const uint8_t> data) override;

		void sendDataToDeviceSocket(std::span<const uint8_t> data) override;

		void forcefullyCloseAll() override;

		[[nodiscard]] bool canRemove() const override;
};
