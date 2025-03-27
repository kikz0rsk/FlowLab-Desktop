#include "client_forwarder.h"

#include <botan/auto_rng.h>
#include "logger.h"

ClientForwarder::ClientForwarder(
	std::string serverName,
	uint16_t port,
	DataReceivedCallback dataReceivedCallback,
	DataReadyCallback dataReadyCallback,
	TlsAlertCallback tlsAlertCallback,
	CertificateNotifyCallback certificateNotifyCallback
) :
	dataReceivedCallback(std::move(dataReceivedCallback)),
	dataReadyCallback(std::move(dataReadyCallback)),
	tlsAlertCallback(std::move(tlsAlertCallback)),
	certificateNotifyCallback(std::move(certificateNotifyCallback)),
	serverName(std::move(serverName)),
	serverPort(port) {
	std::shared_ptr<Botan::AutoSeeded_RNG> rng = std::make_shared<Botan::AutoSeeded_RNG>();
	std::shared_ptr<Botan::TLS::Session_Manager_In_Memory> session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
	std::shared_ptr<ClientForwarderCredentials> creds = std::make_shared<ClientForwarderCredentials>();
	std::shared_ptr<Botan::TLS::Policy> policy = std::make_shared<Botan::TLS::Default_Policy>();
	std::shared_ptr<Botan::TLS::Callbacks> callbacks = std::make_shared<ClientForwarderCallbacks>(
		this->dataReceivedCallback,
		this->dataReadyCallback,
		this->tlsAlertCallback,
		this->certificateNotifyCallback
	);
	this->client = std::make_shared<Botan::TLS::Client>(
		callbacks,
		session_mgr,
		creds,
		policy,
		rng,
		this->serverName.empty() ? Botan::TLS::Server_Information() : Botan::TLS::Server_Information(this->serverName, this->serverPort)
	);
}

ClientForwarder::ClientForwarderCallbacks::ClientForwarderCallbacks(
	DataReceivedCallback dataReceivedCallback,
	DataReadyCallback dataReadyCallback,
	TlsAlertCallback tlsAlertCallback,
	CertificateNotifyCallback certificateNotifyCallback
) : dataReceivedCallback(std::move(dataReceivedCallback)),
		dataReadyCallback(std::move(dataReadyCallback)),
		tlsAlertCallback(std::move(tlsAlertCallback)),
		certificateNotifyCallback(std::move(certificateNotifyCallback)) {}

void ClientForwarder::ClientForwarderCallbacks::tls_emit_data(std::span<const uint8_t> data) {
	this->dataReadyCallback(data);
}

void ClientForwarder::ClientForwarderCallbacks::tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) {
	this->dataReceivedCallback(seq_no, data);
}

void ClientForwarder::ClientForwarderCallbacks::tls_alert(Botan::TLS::Alert alert) {
	this->tlsAlertCallback(alert);
}

void ClientForwarder::ClientForwarderCallbacks::tls_verify_cert_chain(
	const std::vector<Botan::X509_Certificate> &cert_chain,
	const std::vector<std::optional<Botan::OCSP::Response>> &ocsp_responses,
	const std::vector<Botan::Certificate_Store *> &trusted_roots,
	Botan::Usage_Type usage,
	std::string_view hostname,
	const Botan::TLS::Policy &policy
) {
	if (cert_chain.empty()) {
		throw Botan::Invalid_Argument("Certificate chain was empty");
	}

	// Botan::Path_Validation_Restrictions restrictions(false, policy.minimum_signature_strength());
	//
	// Botan::Path_Validation_Result result = x509_path_validate(
	// 	cert_chain,
	// 	restrictions,
	// 	trusted_roots,
	// 	hostname,
	// 	usage,
	// 	tls_current_timestamp(),
	// 	tls_verify_cert_chain_ocsp_timeout(),
	// 	ocsp_responses
	// );
	//
	// if (!result.successful_validation()) {
	// 	Logger::get().log("[TLS Proxy Client] Certificate validation failure: " + result.result_string());
	// 	throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::BadCertificate, "Certificate validation failure: " + result.result_string());
	// }

	this->certificateNotifyCallback(cert_chain[0]);
}

std::vector<Botan::Certificate_Store *> ClientForwarder::ClientForwarderCredentials::trusted_certificate_authorities(const std::string &type, const std::string &context) {
	return {&caCertStore};
}

std::vector<Botan::X509_Certificate> ClientForwarder::ClientForwarderCredentials::cert_chain(
	const std::vector<std::string> &cert_key_types,
	const std::vector<Botan::AlgorithmIdentifier> &cert_signature_schemes,
	const std::string &type,
	const std::string &context
) {
	return {};
}

std::shared_ptr<Botan::Private_Key> ClientForwarder::ClientForwarderCredentials::private_key_for(
	const Botan::X509_Certificate &cert,
	const std::string &type,
	const std::string &context
) {
	return nullptr;
}
