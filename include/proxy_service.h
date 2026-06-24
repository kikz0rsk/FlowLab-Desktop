#pragma once

#include <memory>
#include <thread>
#include <list>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/signals2/signal.hpp>
#include <botan/certstor.h>
#include <botan/credentials_manager.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/x509path.h>

#include <tracy/Tracy.hpp>

class Client;
class FileWriter;
class Connection;
class TcpConnection;

namespace ndpi {
	struct ndpi_detection_module_struct;
}

class DnsManager;
class ConnectionManager;

class ProxyService : public std::enable_shared_from_this<ProxyService> {
	public:
		static constexpr int DEFAULT_PORT = 20'000;

		class ServerCallbacks : public Botan::TLS::Callbacks {
			protected:
				Client& client;
				boost::asio::io_context& ioContext;

			public:
				explicit ServerCallbacks(Client& client, boost::asio::io_context& ioContext);

				void tls_emit_data(std::span<const uint8_t> data) override;

				void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override;

				void tls_alert(Botan::TLS::Alert alert) override;

				void tls_verify_cert_chain(
					const std::vector<Botan::X509_Certificate> &cert_chain,
					const std::vector<std::optional<Botan::OCSP::Response>> &ocsp_responses,
					const std::vector<Botan::Certificate_Store *> &trusted_roots,
					Botan::Usage_Type usage,
					std::string_view hostname,
					const Botan::TLS::Policy &policy
				) override;
		};

		class ServerCredentials : public Botan::Credentials_Manager {
			protected:
				Botan::Certificate_Store_In_Memory caCertStore;
				std::shared_ptr<Botan::X509_Certificate> serverCert;
				std::shared_ptr<Botan::X509_Certificate> caCert;
				std::shared_ptr<Botan::Private_Key> serverKey;

			public:
				explicit ServerCredentials(
					std::shared_ptr<Botan::X509_Certificate> serverCert,
					std::shared_ptr<Botan::X509_Certificate> caCert,
					std::shared_ptr<Botan::Private_Key> serverKey
				);

				std::vector<Botan::Certificate_Store *> trusted_certificate_authorities(
					const std::string& type,
					const std::string& context
				) override;

				std::vector<Botan::X509_Certificate> cert_chain(
					const std::vector<std::string>& cert_key_types,
					const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
					const std::string& type,
					const std::string& context
				) override;

				std::shared_ptr<Botan::Private_Key> private_key_for(
					const Botan::X509_Certificate& cert,
					const std::string& type,
					const std::string& context
				) override;
		};

		static std::shared_ptr<Botan::Private_Key> tlsProxyKey;

	protected:
		boost::asio::io_context ioContext;
		std::optional<boost::asio::ip::tcp::acceptor> tcpAcceptor;

		std::list<std::shared_ptr<Client>> clients;
		std::jthread thread;
		std::atomic_bool stopFlag = false;
		std::atomic_bool running = false;
		std::shared_ptr<FileWriter> fileWriter;
		ndpi::ndpi_detection_module_struct *ndpi;
		std::shared_ptr<DnsManager> dnsManager;
		std::atomic_bool enableTlsRelay = true;
		boost::signals2::signal<void(bool, std::shared_ptr<Client>, unsigned int)> deviceConnectionSignal;
		boost::signals2::signal<void(bool, std::shared_ptr<Connection>)> connectionAddedSignal;
		boost::signals2::signal<void(bool, std::shared_ptr<TcpConnection>)> tlsConnectionAddedSignal;
		std::shared_ptr<Botan::X509_Certificate> serverCert;
		std::shared_ptr<Botan::X509_Certificate> caCert;
		std::shared_ptr<Botan::Private_Key> serverKey;

	public:
		ProxyService();
		~ProxyService();

		void start();
		void stop();

		[[nodiscard]] boost::signals2::signal<void(bool, std::shared_ptr<Connection>)>& getConnectionAddedSignal() {
			return connectionAddedSignal;
		}

		[[nodiscard]] boost::signals2::signal<void(bool, std::shared_ptr<TcpConnection>)>& getTlsConnectionAddedSignal() {
			return tlsConnectionAddedSignal;
		}

		[[nodiscard]] std::shared_ptr<DnsManager> getDnsManager() const;

		[[nodiscard]] std::shared_ptr<FileWriter> getPcapWriter() const;

		[[nodiscard]] ndpi::ndpi_detection_module_struct *getNdpiStruct();

		[[nodiscard]] boost::signals2::signal<void(bool, std::shared_ptr<Client>, unsigned int)>& getDeviceConnectionSignal();

		[[nodiscard]] bool isRunning() const;

	protected:
		boost::asio::awaitable<void>  acceptLoop();

		boost::asio::awaitable<void> handleClient(boost::asio::ip::tcp::socket socket);

		bool sendFromDevice(std::shared_ptr<Client> client);
		void cleanUpAfterClient(std::shared_ptr<Client> client);

	public:
		boost::asio::io_context& getIoContext();
		void setEnableTlsRelay(bool enable);
		[[nodiscard]] bool getEnableTlsRelay() const;
};
