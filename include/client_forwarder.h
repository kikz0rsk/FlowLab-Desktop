#pragma once

#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/x509path.h>

#include "logger.h"

class ClientForwarder {
	public:
		ClientForwarder() = default;

		class ClientForwarderCallbacks : public Botan::TLS::Callbacks {
			protected:
				Client& client;
			public:
				explicit ClientForwarderCallbacks(Client& client) : client(client) {}

				void tls_emit_data(std::span<const uint8_t> data) override {
					Logger::get().log("Queueing " + std::to_string(data.size()) + " TLS bytes to client");
					client.getEncryptedQueueToDevice().insert(client.getEncryptedQueueToDevice().end(), data.begin(), data.end());
				}

				void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override {
					Logger::get().log("Received " + std::to_string(data.size()) + " data bytes from client");
					client.getUnencryptedQueueFromDevice().insert(client.getUnencryptedQueueFromDevice().end(), data.begin(), data.end());
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

		class ClientForwarderCredentials : public Botan::Credentials_Manager {
			protected:
				Botan::Certificate_Store_In_Memory caCertStore;
			public:
				explicit ClientForwarderCredentials() = default;

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
					return {};
				}

				std::shared_ptr<Botan::Private_Key> private_key_for(
					const Botan::X509_Certificate& cert,
					const std::string& type,
					const std::string& context
				) override {
					return nullptr;
				}
		};
};
