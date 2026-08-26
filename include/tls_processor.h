#pragma once

#include <deque>
#include <memory>
#include <span>

#include "iprocessor.h"

namespace Botan {
	namespace TLS {
		class Alert;
	}

	class X509_Certificate;
}

class ClientForwarder;
class ServerForwarder;
class TcpConnection;
struct ProcessorInitContext;
struct ProcessorRuntimeContext;

class TlsProcessor : public IProcessor {
	public:
		constexpr static const char *META_TLS_RELAY = "tlsProcessor_tlsRelay";

		struct State {
			bool ready = false;
			std::vector<std::string> domains;
			std::vector<uint8_t> tlsHandshakeBuffer{};
			std::string serverNameIndication{};
			std::deque<uint8_t> unencryptedStream{};
			std::string tlsRelayStatus = "Unknown";
			uint16_t clientHandshakeRecordSize = 0;

			std::shared_ptr<ServerForwarder> serverTlsForwarder{};
			std::shared_ptr<ClientForwarder> clientTlsForwarder{};

			// input - data received
			// output - data to send

			std::vector<uint8_t> tlsClientOutputBuffer{};
			std::vector<uint8_t> tlsClientInputBuffer{};
			std::vector<uint8_t> tlsServerOutputBuffer{};
			std::vector<uint8_t> tlsServerInputBuffer{};
		};

	private:
		State state{};
		std::weak_ptr<TcpConnection> conn{};

	public:
		TlsProcessor();
		~TlsProcessor() override = default;

		void init(const ProcessorInitContext&) override;

		std::vector<uint8_t> processDataToSocket(std::span<const uint8_t> data, ProcessorRuntimeContext &context, NextForwarderCallback next) override;
		std::vector<uint8_t> processDataToDevice(std::span<const uint8_t> data, ProcessorRuntimeContext &context, NextForwarderCallback next) override;

		std::string getServerNameIndication() const;
		std::string getTlsRelayStatus() const;
		std::vector<std::string> getDomains() const;
		const State& getState() const;

	private:
		void onTlsClientDataToSend(std::span<const uint8_t> data);
		void onTlsClientDataReceived(std::span<const uint8_t> data);
		void onTlsClientAlert(Botan::TLS::Alert alert);
		void onTlsClientGotCertificate(const Botan::X509_Certificate &cert);

		void onTlsServerDataReceived(std::span<const uint8_t> data);
		void onTlsServerDataToSend(std::span<const uint8_t> data);
		void onTlsServerAlert(Botan::TLS::Alert alert);
		void onTlsServerSuccess();

		void initTlsClient(uint16_t dstPort);
		void initTlsServer(const Botan::X509_Certificate &cert);
		std::vector<uint8_t> takeBuffer(std::vector<uint8_t> &buffer);
};
