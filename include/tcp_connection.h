#pragma once

#include <QStandardItemModel>
#include <regex>
#include <thread>

#include "client.h"
#include "connection.h"
#include "tcp_state.h"
#include "tcp_status.h"

class ProxyService;
class ServerForwarder;
class ClientForwarder;

class TcpConnection : public Connection {
	protected:
		static constexpr const char *SERVER_TAG = "SERVER>>>>>>>>>";
		static constexpr const char *CLIENT_TAG = "CLIENT>>>>>>>>>";

		std::shared_ptr<ServerForwarder> serverTlsForwarder{};
		std::shared_ptr<ClientForwarder> clientTlsForwarder{};
		bool hasCertificate = false;
		bool doTlsRelay = false;

		std::vector<uint8_t> tlsBuffer{};
		std::string serverNameIndication{};
		std::deque<uint8_t> unencryptedStream{};
		std::string tlsRelayStatus = "Unknown";
		uint16_t clientHandshakeRecordSize = 0;
		std::ofstream unencryptedFileStream;
		std::string lastTag;
		std::string filePath;

		boost::asio::ip::tcp::socket destSocket;
		TcpState tcpState{};
		TcpStatus tcpStatus = TcpStatus::CLOSED;

	public:
		TcpConnection(
			std::shared_ptr<ProxyService> proxyService,
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

		boost::asio::awaitable<void> processPacketFromDevice(pcpp::Layer *networkLayer) override;

		boost::asio::awaitable<void> openSocket();

		void sendAck();

		boost::asio::awaitable<void> sendDataToRemote(std::span<const uint8_t> data) override;

		boost::asio::awaitable<std::vector<uint8_t>> read() override;

		std::unique_ptr<pcpp::Packet> encapsulateResponseDataToPacket(std::span<const uint8_t> data) override;

		void sendDataToDeviceSocket(std::span<const uint8_t> data) override;

		void sendRst(bool ack = false);

		// [[nodiscard]]  static unsigned long getBytesAvailable(SOCKET socket);

		[[nodiscard]] TcpStatus getTcpStatus() const;

		void setTcpStatus(TcpStatus tcpStatus);

		void forcefullyCloseAll() override;

		[[nodiscard]] bool canRemove() const override;

		void onTlsClientDataToSend(std::span<const uint8_t> data);
		void onTlsClientDataReceived(std::span<const uint8_t> data);
		void onTlsClientAlert(Botan::TLS::Alert alert);
		void onTlsClientGotCertificate(const Botan::X509_Certificate &cert);

		void onTlsServerDataReceived(std::span<const uint8_t> data);
		void onTlsServerDataToSend(std::span<const uint8_t> data);
		void onTlsServerAlert(Botan::TLS::Alert alert);
		void onTlsServerSuccess();

		void initTlsClient();
		void initTlsServer(const Botan::X509_Certificate &cert);

		const std::string& getServerNameIndication();
		const std::deque<uint8_t>& getUnencryptedStream();
		const std::string& getTlsRelayStatus() const;

		std::set<std::string>& getDomains();

		void logToFile() override;

		template<typename ByteT>
		void replaceBytes(
			std::vector<ByteT>& data,
			const std::vector<ByteT>& search,
			const std::vector<ByteT>& replacement
		)	{
			if (search.empty()){
				return;
			}
			auto it = data.begin();
			while (true) {
				auto pos = std::search(it, data.end(), search.begin(), search.end());
				if (pos == data.end()) {
					break;
				}

				pos = data.erase(pos, pos + search.size());
				pos = data.insert(pos, replacement.begin(), replacement.end());
				it = pos + replacement.size();
			}
		}

		void regexReplace(
			std::vector<uint8_t>& data,
			const std::regex& pat,
			const std::string& repl
		) {
			std::string s(reinterpret_cast<char *>(data.data()), data.size());
			std::string out = std::regex_replace(s, pat, repl);
			data.assign(out.begin(), out.end());
		}
};
