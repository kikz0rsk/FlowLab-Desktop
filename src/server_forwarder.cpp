#include "server_forwarder.h"

#include <botan/tls_session_manager_memory.h>
#include <botan/x509_ext.h>

#include "logger.h"

ServerForwarderCredentials::ServerForwarderCredentials() = default;

std::vector<Botan::Certificate_Store *> ServerForwarderCredentials::trusted_certificate_authorities(const std::string &type, const std::string &context) {
	return {};
}

std::vector<Botan::X509_Certificate> ServerForwarderCredentials::cert_chain(
	const std::vector<std::string> &cert_key_types,
	const std::vector<Botan::AlgorithmIdentifier> &cert_signature_schemes,
	const std::string &type,
	const std::string &context
) {
	// use generated certificate and key
	return {*generatedCert, *caCert};
}

std::shared_ptr<Botan::Private_Key> ServerForwarderCredentials::private_key_for(const Botan::X509_Certificate &cert, const std::string &type, const std::string &context) {
	return this->generatedKey;
}

ServerForwarder::ServerForwarder(
	const Botan::X509_Certificate &origCert,
	DataReceivedCallback dataReceivedCallback,
	DataReadyCallback dataReadyCallback,
	TlsAlertCallback tlsAlertCallback,
	SuccessCallback successCallback
) :
	dataReceivedCallback(std::move(dataReceivedCallback)),
	dataReadyCallback(std::move(dataReadyCallback)),
	tlsAlertCallback(std::move(tlsAlertCallback)),
	successCallback(std::move(successCallback)),
	originalCert(origCert) {
	caCert = Botan::X509_Certificate(R"(flowlab_ca.cer)");
	Botan::DataSource_Stream in(R"(flowlab_ca.pkcs8)");
	caKey = Botan::PKCS8::load_key(in);

	auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
	this->creds = std::make_shared<ServerForwarderCredentials>();

	this->generatedKey = ProxyService::tlsProxyKey;
	Botan::X509_Cert_Options options{};
	options.start = originalCert.not_before();
	options.end = originalCert.not_after();
	if (!originalCert.subject_info("X520.CommonName").empty()) {
		options.common_name = originalCert.subject_info("X520.CommonName").at(0);
	}
	if (!originalCert.subject_info("X520.Country").empty()) {
		options.country = originalCert.subject_info("X520.Country").at(0);
	}
	if (!originalCert.subject_info("X520.Organization").empty()) {
		options.organization = originalCert.subject_info("X520.Organization").at(0);
	}
	if (!originalCert.subject_info("X509.Certificate.serial").empty()) {
		options.serial_number = originalCert.subject_info("X509.Certificate.serial").at(0);
	}
	options.is_CA = false;
	options.constraints = originalCert.constraints();

	auto origSubjectAlternateNames = originalCert.v3_extensions().get(Botan::OID("2.5.29.17"));
	if (origSubjectAlternateNames) {
		options.extensions.add(origSubjectAlternateNames->copy());
	}

	auto certReq = Botan::X509::create_cert_req(options, *this->generatedKey, "SHA-256", *rng);

	const Botan::X509_CA ca(caCert, *caKey, "SHA-256", *rng);
	this->generatedCert = ca.sign_request(certReq, *rng, originalCert.not_before(), originalCert.not_after());
	Logger::get().log("Generated cert: " + this->generatedCert.to_string());
	this->creds->caCert = std::make_shared<Botan::X509_Certificate>(caCert);
	this->creds->generatedCert = std::make_shared<Botan::X509_Certificate>(this->generatedCert);
	this->creds->generatedKey = this->generatedKey;

	auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
	auto policy = std::make_shared<Botan::TLS::Strict_Policy>();
	std::shared_ptr<Botan::TLS::Callbacks> callbacks = std::make_shared<ServerForwarderCallbacks>(
		this->dataReceivedCallback,
		this->dataReadyCallback,
		this->tlsAlertCallback,
		this->successCallback
	);

	server = std::make_shared<Botan::TLS::Server>(callbacks, session_mgr, creds, policy, rng);
}

ServerForwarder::ServerForwarderCallbacks::ServerForwarderCallbacks(
	DataReceivedCallback dataReceivedCallback,
	DataReadyCallback dataReadyCallback,
	TlsAlertCallback tlsAlertCallback,
	SuccessCallback successCallback
) : dataReceivedCallback(std::move(dataReceivedCallback)),
		dataReadyCallback(std::move(dataReadyCallback)),
		tlsAlertCallback(std::move(tlsAlertCallback)),
		successCallback(std::move(successCallback)) {}

void ServerForwarder::ServerForwarderCallbacks::tls_emit_data(std::span<const uint8_t> data) {
	this->dataReadyCallback(data);
}

void ServerForwarder::ServerForwarderCallbacks::tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) {
	this->dataReceivedCallback(seq_no, data);
}

void ServerForwarder::ServerForwarderCallbacks::tls_alert(Botan::TLS::Alert alert) {
	this->tlsAlertCallback(alert);
}

void ServerForwarder::ServerForwarderCallbacks::tls_session_activated() {
	this->successCallback();
}
