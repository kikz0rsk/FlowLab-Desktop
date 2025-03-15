#pragma once

#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/x509path.h>
#include <botan/tls_alert.h>
#include <botan/tls_client.h>
#include <botan/tls.h>
#include <botan/certstor_system.h>

#include "logger.h"

class ClientForwarder {
	public:
		using DataReceivedCallback = std::function<void (uint64_t seq_no, std::span<const uint8_t> data)>;
		using DataReadyCallback = std::function<void (std::span<const uint8_t> data)>;
		using TlsAlertCallback = std::function<void (Botan::TLS::Alert alert)>;
		using CertificateNotifyCallback = std::function<void (const Botan::X509_Certificate &cert)>;

	protected:
		DataReceivedCallback dataReceivedCallback;
		DataReadyCallback dataReadyCallback;
		TlsAlertCallback tlsAlertCallback;
		CertificateNotifyCallback certificateNotifyCallback;
		std::shared_ptr<Botan::TLS::Client> client;

	public:
		ClientForwarder(
			DataReceivedCallback dataReceivedCallback,
			DataReadyCallback dataReadyCallback,
			TlsAlertCallback tlsAlertCallback,
			CertificateNotifyCallback certificateNotifyCallback
		) :
			dataReceivedCallback(std::move(dataReceivedCallback)),
			dataReadyCallback(std::move(dataReadyCallback)),
			tlsAlertCallback(std::move(tlsAlertCallback)),
			certificateNotifyCallback(std::move(certificateNotifyCallback)) {
			std::shared_ptr<Botan::AutoSeeded_RNG> rng = std::make_shared<Botan::AutoSeeded_RNG>();
			std::shared_ptr<Botan::TLS::Session_Manager_In_Memory> session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
			std::shared_ptr<ClientForwarderCredentials> creds = std::make_shared<ClientForwarderCredentials>();
			std::shared_ptr<Botan::TLS::Strict_Policy> policy = std::make_shared<Botan::TLS::Strict_Policy>();
			std::shared_ptr<Botan::TLS::Callbacks> callbacks = std::make_shared<ClientForwarderCallbacks>(
				this->dataReceivedCallback,
				this->dataReadyCallback,
				this->tlsAlertCallback,
				this->certificateNotifyCallback
			);
			this->client = std::make_shared<Botan::TLS::Client>(callbacks, session_mgr, creds, policy, rng);
		}

		class ClientForwarderCallbacks : public Botan::TLS::Callbacks {
			protected:
				DataReceivedCallback dataReceivedCallback;
				DataReadyCallback dataReadyCallback;
				TlsAlertCallback tlsAlertCallback;
				CertificateNotifyCallback certificateNotifyCallback;

			public:
				explicit ClientForwarderCallbacks(
					DataReceivedCallback dataReceivedCallback,
					DataReadyCallback dataReadyCallback,
					TlsAlertCallback tlsAlertCallback,
					CertificateNotifyCallback certificateNotifyCallback
				) : dataReceivedCallback(std::move(dataReceivedCallback)),
						dataReadyCallback(std::move(dataReadyCallback)),
						tlsAlertCallback(std::move(tlsAlertCallback)),
						certificateNotifyCallback(std::move(certificateNotifyCallback))	{}

				void tls_emit_data(std::span<const uint8_t> data) override {
					this->dataReadyCallback(std::move(data));
				}

				void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override {
					this->dataReceivedCallback(seq_no, std::move(data));
				}

				void tls_alert(Botan::TLS::Alert alert) override {
					this->tlsAlertCallback(std::move(alert));
				}

				void tls_verify_cert_chain(
					const std::vector<Botan::X509_Certificate> &cert_chain,
					const std::vector<std::optional<Botan::OCSP::Response>> &ocsp_responses,
					const std::vector<Botan::Certificate_Store *> &trusted_roots,
					Botan::Usage_Type usage,
					std::string_view hostname,
					const Botan::TLS::Policy &policy
				) override {
					if (cert_chain.empty()) {
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

					if (!result.successful_validation()) {
						Logger::get().log("[TLS Proxy Client] Certificate validation failure: " + result.result_string());
						throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::BadCertificate, "Certificate validation failure: " + result.result_string());
					}

					this->certificateNotifyCallback(cert_chain[0]);
				}
		};

		class ClientForwarderCredentials : public Botan::Credentials_Manager {
			protected:
				Botan::System_Certificate_Store caCertStore;

			public:
				explicit ClientForwarderCredentials() = default;

				std::vector<Botan::Certificate_Store *> trusted_certificate_authorities(
					const std::string &type,
					const std::string &context
				) override {
					return {&caCertStore};
				}

				std::vector<Botan::X509_Certificate> cert_chain(
					const std::vector<std::string> &cert_key_types,
					const std::vector<Botan::AlgorithmIdentifier> &cert_signature_schemes,
					const std::string &type,
					const std::string &context
				) override {
					return {};
				}

				std::shared_ptr<Botan::Private_Key> private_key_for(
					const Botan::X509_Certificate &cert,
					const std::string &type,
					const std::string &context
				) override {
					return nullptr;
				}
		};

		[[nodiscard]] std::shared_ptr<Botan::TLS::Client> & getClient() {
			return client;
		}
};
