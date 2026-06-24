#include "proxy_service.h"

#include <iostream>
#include <filesystem>
#include <pcapplusplus/IPv4Layer.h>
#include <botan/pk_algs.h>
#include <botan/tls_session_manager_memory.h>
#include <pcapplusplus/DnsLayer.h>
#include <boost/asio.hpp>
#include <botan/auto_rng.h>

#include "connection_manager.h"
#include "dns_manager.h"
#include "tracy/Tracy.hpp"

#include "logger.h"
#include "file_writer.h"
#include "socket_utils.h"
#include "tcp_connection.h"
#include "udp_connection.h"

ProxyService::ServerCallbacks::ServerCallbacks(Client &client, boost::asio::io_context& ioContext) : client(client), ioContext(ioContext) {}

void ProxyService::ServerCallbacks::tls_emit_data(std::span<const uint8_t> data) {
	ZoneScoped;
	// Logger::get().log("Queueing " + std::to_string(data.size()) + " TLS bytes to client");
	// queue encrypted TLS data to device
	client.getEncryptedQueueToDevice().insert(client.getEncryptedQueueToDevice().end(), data.begin(), data.end());
	if (!client.isWriteTlsActive()) {
		boost::asio::co_spawn(
			this->ioContext,
			[this]() -> boost::asio::awaitable<void> {
				co_await this->client.writeTls();
			},
			boost::asio::detached
		);
	}
}

void ProxyService::ServerCallbacks::tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) {
	ZoneScoped;
	// Logger::get().log("Received " + std::to_string(data.size()) + " data bytes from client");
	// queue decrypted data from device
	client.getUnencryptedQueueFromDevice().insert(client.getUnencryptedQueueFromDevice().end(), data.begin(), data.end());
	client.processIncomingData();
}

void ProxyService::ServerCallbacks::tls_alert(Botan::TLS::Alert alert) {
	Logger::get().log("TLS alert: " + alert.type_string());
}

void ProxyService::ServerCallbacks::tls_verify_cert_chain(
	const std::vector<Botan::X509_Certificate> &cert_chain,
	const std::vector<std::optional<Botan::OCSP::Response>> &ocsp_responses,
	const std::vector<Botan::Certificate_Store *> &trusted_roots,
	Botan::Usage_Type usage,
	std::string_view hostname,
	const Botan::TLS::Policy &policy
) {
	if(cert_chain.empty()) {
		throw Botan::Invalid_Argument("Certificate chain was empty");
	}

	Botan::Path_Validation_Restrictions restrictions(false, policy.minimum_signature_strength());

	Botan::Path_Validation_Result result = x509_path_validate(
		cert_chain,
		restrictions,
		trusted_roots,
		hostname,
		usage,
		tls_current_timestamp(),
		tls_verify_cert_chain_ocsp_timeout(),
		ocsp_responses
	);

	if(!result.successful_validation()) {
		Logger::get().log("Certificate validation failure: " + result.result_string());
		throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::BadCertificate, "Certificate validation failure: " + result.result_string());
	}
}

ProxyService::ServerCredentials::ServerCredentials(
	std::shared_ptr<Botan::X509_Certificate> serverCert,
	std::shared_ptr<Botan::X509_Certificate> caCert,
	std::shared_ptr<Botan::Private_Key> serverKey
) :
	serverCert(std::move(serverCert)),
	caCert(std::move(caCert)),
	serverKey(std::move(serverKey)) {
	caCertStore.add_certificate(*this->caCert);
}

std::vector<Botan::Certificate_Store *> ProxyService::ServerCredentials::trusted_certificate_authorities(const std::string &type, const std::string &context) {
	return {&caCertStore};
}

std::vector<Botan::X509_Certificate> ProxyService::ServerCredentials::cert_chain(
	const std::vector<std::string> &cert_key_types,
	const std::vector<Botan::AlgorithmIdentifier> &cert_signature_schemes,
	const std::string &type,
	const std::string &context
) {
	return {*serverCert, *caCert};
}

std::shared_ptr<Botan::Private_Key> ProxyService::ServerCredentials::private_key_for(const Botan::X509_Certificate &cert, const std::string &type, const std::string &context) {
	return serverKey;
}

std::shared_ptr<Botan::Private_Key> ProxyService::tlsProxyKey {};

ProxyService::ProxyService() : ioContext(1), ndpi(ndpi::ndpi_init_detection_module(nullptr)) {
	dnsManager = std::make_shared<DnsManager>();

	if (ndpi == nullptr) {
		throw std::runtime_error("Failed to initialize nDPI");
	}
	ndpi::ndpi_protocol_bitmask_struct_t all{};
	NDPI_BITMASK_SET_ALL(all);
	int res = ndpi::ndpi_set_protocol_detection_bitmask2(ndpi, &all);
	if (res != 0) {
		throw std::runtime_error("Failed to set protocol detection bitmask");
	}
	res = ndpi::ndpi_finalize_initialization(ndpi);
	if (res != 0) {
		throw std::runtime_error("Failed to finalize nDPI initialization");
	}
}

ProxyService::~ProxyService() {
	stop();
	ndpi::ndpi_exit_detection_module(ndpi);
}

void ProxyService::start() {
	running = true;
	std::filesystem::create_directories("tls-streams");
	serverCert = std::make_shared<Botan::X509_Certificate>(R"(flowlab_server_flowlab_ca.cer)");
	caCert = std::make_shared<Botan::X509_Certificate>(R"(flowlab_ca.cer)");
	Botan::DataSource_Stream in(R"(flowlab_server_flowlab_ca.pkcs8)");
	serverKey.reset(Botan::PKCS8::load_key(in).release());

	Botan::AutoSeeded_RNG rng{};
	Logger::get().log("Generating RSA key pair for TLS proxy");
	tlsProxyKey = Botan::create_private_key("RSA", rng, "2048");
	Logger::get().log("Done generating key pair");
	stopFlag = false;

	try {
		this->fileWriter = std::make_shared<FileWriter>();
	} catch (const std::exception& e) {
		Logger::get().log("Cannot open file for writing: " + std::string(e.what()));
		std::cerr << "Cannot open file for writing: " + std::string(e.what()) << std::endl;
		running = false;

		return;
	}

	std::cerr << "starting" << std::endl;
	tcpAcceptor = boost::asio::ip::tcp::acceptor(this->ioContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), DEFAULT_PORT));
	boost::asio::signal_set sig(this->ioContext, SIGINT, SIGTERM);
	sig.async_wait([&](const boost::system::error_code &ec, int) {
		if (ec) {
			return;
		}
		stopFlag = true;
		ioContext.stop();
	});
	boost::asio::co_spawn(
		this->ioContext,
		[this] -> boost::asio::awaitable<void> {
			return this->acceptLoop();
		},
		boost::asio::detached
	);

	thread = std::jthread(
		[this] {
			this->ioContext.run();
		}
	);
}

void ProxyService::stop() {
	running = false;
	stopFlag = true;
	ioContext.stop();
	if (thread.joinable()) {
		thread.join();
	}
	for (const auto& client : clients) {
		for (auto& conn : client->getConnectionManager()->getConnections()) {
			if (conn.second->getRemoteSocketStatus() == RemoteSocketStatus::CLOSED) {
				continue;
			}
			conn.second->gracefullyCloseRemoteSocket();
		}
	}
}

std::shared_ptr<DnsManager> ProxyService::getDnsManager() const {
	return dnsManager;
}

std::shared_ptr<FileWriter> ProxyService::getPcapWriter() const {
	return fileWriter;
}

ndpi::ndpi_detection_module_struct * ProxyService::getNdpiStruct() {
	return ndpi;
}

boost::signals2::signal<void(bool, std::shared_ptr<Client>, unsigned int)>& ProxyService::getDeviceConnectionSignal() {
	return deviceConnectionSignal;
}

bool ProxyService::isRunning() const {
	return running.load();
}

boost::asio::awaitable<void> ProxyService::acceptLoop() {
	// setStatusBarMessage("Socket ready on port " + std::to_string(ntohs(addr.sin_port)));

	while (!stopFlag.load()) {
		try {
			boost::asio::ip::tcp::socket socket(this->ioContext);
			co_await this->tcpAcceptor->async_accept(socket, boost::asio::use_awaitable);
			boost::asio::co_spawn(this->ioContext, [this, socket = std::move(socket)] mutable -> boost::asio::awaitable<void> {
				co_await handleClient(std::move(socket));
			}, boost::asio::detached);
		} catch (const std::exception &e) {}
	}

	co_return;
}

boost::asio::awaitable<void> ProxyService::handleClient(boost::asio::ip::tcp::socket socket) {
	ZoneScoped;

	auto remote = socket.remote_endpoint();
	const std::string address = remote.address().to_string();

	auto client = this->clients.emplace_back(std::make_shared<Client>(weak_from_this(), std::move(socket), pcpp::IPAddress(address), remote.port()));

	// Fan this client's per-connection signals up into the aggregate signals the GUI subscribes to.
	// The slots are owned by the client's ConnectionManager signals, so they auto-disconnect when the
	// client is destroyed. `this` (ProxyService) always outlives every client, so there is no dangling.
	const auto connectionManager = client->getConnectionManager();
	connectionManager->getConnectionAddedSignal().connect(
		[this](bool added, std::shared_ptr<Connection> connection) {
			connectionAddedSignal(added, std::move(connection));
		}
	);
	connectionManager->getTlsConnectionAddedSignal().connect(
		[this](bool added, std::shared_ptr<TcpConnection> connection) {
			tlsConnectionAddedSignal(added, std::move(connection));
		}
	);

	const std::shared_ptr<Botan::AutoSeeded_RNG> rng = std::make_shared<Botan::AutoSeeded_RNG>();
	const std::shared_ptr<Botan::TLS::Session_Manager_In_Memory> session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
	const std::shared_ptr<ServerCredentials> creds = std::make_shared<ServerCredentials>(this->serverCert, this->caCert, this->serverKey);
	const std::shared_ptr<Botan::TLS::Strict_Policy> policy = std::make_shared<Botan::TLS::Strict_Policy>();
	const std::shared_ptr<Botan::TLS::Callbacks> callbacks = std::make_shared<ServerCallbacks>(*client, this->ioContext);
	auto server = std::make_shared<Botan::TLS::Server>(callbacks, session_mgr, creds, policy, rng);
	client->setTlsServer(server);
	this->deviceConnectionSignal(true, client, this->clients.size());
	Logger::get().log(std::format("Accepted client from {}", address));
	co_await client->handleClient();
	const auto itr = std::ranges::find(this->clients, client);
	if (itr != this->clients.end()) {
		this->clients.erase(itr);
	}
	cleanUpAfterClient(client);
}

void ProxyService::cleanUpAfterClient(std::shared_ptr<Client> client) {
	for (const auto& conn : client->getConnectionManager()->getConnections()) {
		conn.second->forcefullyCloseAll();
	}
	this->deviceConnectionSignal(false, client, this->clients.empty() ? 0 : this->clients.size() - 1);
}

boost::asio::io_context & ProxyService::getIoContext() {
	return this->ioContext;
}

void ProxyService::setEnableTlsRelay(bool enable) {
	this->enableTlsRelay = enable;
}

bool ProxyService::getEnableTlsRelay() const {
	return this->enableTlsRelay.load();
}
