#pragma once

#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/x509path.h>

#include "logger.h"

class ServerForwarder {
	protected:
		std::shared_ptr<Botan::TLS::Server> server;

	public:
		ServerForwarder() {
			std::shared_ptr<Botan::AutoSeeded_RNG> rng = std::make_shared<Botan::AutoSeeded_RNG>();
			std::shared_ptr<Botan::TLS::Session_Manager_In_Memory> session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
			std::shared_ptr<ServerForwarderCredentials> creds = std::make_shared<ServerForwarderCredentials>();
			std::shared_ptr<Botan::TLS::Strict_Policy> policy = std::make_shared<Botan::TLS::Strict_Policy>();
			std::shared_ptr<Botan::TLS::Callbacks> callbacks = std::make_shared<ServerForwarderCallbacks>();
			auto server = std::make_shared<Botan::TLS::Server>(callbacks, session_mgr, creds, policy, rng);
		}

		class ServerForwarderCallbacks : public Botan::TLS::Callbacks {
			public:
				explicit ServerForwarderCallbacks() = default;

				void tls_emit_data(std::span<const uint8_t> data) override {

				}

				void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override {

				}

				void tls_alert(Botan::TLS::Alert alert) override {
					Logger::get().log("TLS alert: " + alert.type_string());
				}

				void tls_verify_cert_chain(
					const std::vector<Botan::X509_Certificate> &cert_chain,
					const std::vector<std::optional<Botan::OCSP::Response>> &ocsp_responses,
					const std::vector<Botan::Certificate_Store *> &trusted_roots,
					Botan::Usage_Type usage,
					std::string_view hostname,
					const Botan::TLS::Policy &policy
				) override {
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
		};

		class ServerForwarderCredentials : public Botan::Credentials_Manager {
			public:
				Botan::X509_Certificate serverCert;

			protected:
				Botan::Certificate_Store_In_Memory caCertStore;
				Botan::X509_Certificate caCert;
				std::shared_ptr<Botan::Private_Key> serverKey;

			public:
				ServerForwarderCredentials() {
					serverCert = Botan::X509_Certificate(R"(flowlab_server_flowlab_ca.cer)");
					caCert = Botan::X509_Certificate(R"(flowlab_ca.cer)");
					Botan::DataSource_Stream in(R"(flowlab_server_flowlab_ca.pkcs8)");
					serverKey.reset(Botan::PKCS8::load_key(in).release());
					caCertStore.add_certificate(caCert);
				}

				std::vector<Botan::Certificate_Store *> trusted_certificate_authorities(
					const std::string& type,
					const std::string& context
				) override {
					return {&caCertStore};
				}

				std::vector<Botan::X509_Certificate> cert_chain(
					const std::vector<std::string>& cert_key_types,
					const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
					const std::string& type,
					const std::string& context
				) override {
					return {serverCert, caCert};
				}

				std::shared_ptr<Botan::Private_Key> private_key_for(
					const Botan::X509_Certificate& cert,
					const std::string& type,
					const std::string& context
				) override {
					return serverKey;
				}
		};
};
