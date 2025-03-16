#pragma once

#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/x509path.h>
#include <botan/x509self.h>
#include <botan/pk_algs.h>
#include <botan/x509_ca.h>
#include <botan/x509_ext.h>
#include <proxy_service.h>

#include "logger.h"

class ServerForwarderCredentials : public Botan::Credentials_Manager {
	public:
		std::shared_ptr<Botan::Private_Key> generatedKey;
		std::shared_ptr<Botan::X509_Certificate> generatedCert;
		std::shared_ptr<Botan::X509_Certificate> caCert;

		ServerForwarderCredentials() = default;

		std::vector<Botan::Certificate_Store *> trusted_certificate_authorities(
			const std::string& type,
			const std::string& context
		) override {
			return {};
		}

		std::vector<Botan::X509_Certificate> cert_chain(
			const std::vector<std::string>& cert_key_types,
			const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
			const std::string& type,
			const std::string& context
		) override {
			// use generated certificate and key
			return {*generatedCert, *caCert};
		}

		std::shared_ptr<Botan::Private_Key> private_key_for(
			const Botan::X509_Certificate& cert,
			const std::string& type,
			const std::string& context
		) override {
			return this->generatedKey;
		}
};

class ServerForwarder {
	public:
		using DataReceivedCallback = std::function<void (uint64_t seq_no, std::span<const uint8_t> data)>;
		using DataReadyCallback = std::function<void (std::span<const uint8_t> data)>;
		using TlsAlertCallback = std::function<void (Botan::TLS::Alert alert)>;

	protected:
		std::shared_ptr<Botan::TLS::Server> server;
		DataReceivedCallback dataReceivedCallback;
		DataReadyCallback dataReadyCallback;
		TlsAlertCallback tlsAlertCallback;
		Botan::X509_Certificate generatedCert;
		Botan::X509_Certificate originalCert;
		std::shared_ptr<Botan::Private_Key> generatedKey;
		Botan::X509_Certificate caCert;
		std::shared_ptr<Botan::Private_Key> caKey;
		std::shared_ptr<ServerForwarderCredentials> creds;

	public:
		ServerForwarder(
			DataReceivedCallback dataReceivedCallback,
			DataReadyCallback dataReadyCallback,
			TlsAlertCallback tlsAlertCallback
		) :
			dataReceivedCallback(std::move(dataReceivedCallback)),
			dataReadyCallback(std::move(dataReadyCallback)),
			tlsAlertCallback(std::move(tlsAlertCallback)) {
			auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
			auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
			auto creds = std::make_shared<ServerForwarderCredentials>();
			auto policy = std::make_shared<Botan::TLS::Strict_Policy>();
			std::shared_ptr<Botan::TLS::Callbacks> callbacks = std::make_shared<ServerForwarderCallbacks>(
				this->dataReceivedCallback,
				this->dataReadyCallback,
				this->tlsAlertCallback
			);
			this->creds = creds;
			server = std::make_shared<Botan::TLS::Server>(callbacks, session_mgr, creds, policy, rng);
			caCert = Botan::X509_Certificate(R"(flowlab_ca.cer)");
			Botan::DataSource_Stream in(R"(flowlab_ca.pkcs8)");
			caKey = Botan::PKCS8::load_key(in);
		}

		class ServerForwarderCallbacks : public Botan::TLS::Callbacks {
			protected:
				DataReceivedCallback dataReceivedCallback;
				DataReadyCallback dataReadyCallback;
				TlsAlertCallback tlsAlertCallback;

			public:
				explicit ServerForwarderCallbacks(
					DataReceivedCallback dataReceivedCallback,
					DataReadyCallback dataReadyCallback,
					TlsAlertCallback tlsAlertCallback
				) : dataReceivedCallback(std::move(dataReceivedCallback)),
						dataReadyCallback(std::move(dataReadyCallback)),
						tlsAlertCallback(std::move(tlsAlertCallback)) {}

				void tls_emit_data(std::span<const uint8_t> data) override {
					this->dataReadyCallback(data);
				}

				void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override {
					this->dataReceivedCallback(seq_no, data);
				}

				void tls_alert(Botan::TLS::Alert alert) override {
					this->tlsAlertCallback(alert);
				}
		};

		void setCertificate(const Botan::X509_Certificate& cert) {
			this->originalCert = cert;

			Botan::AutoSeeded_RNG rng{};
			this->generatedKey = ProxyService::tlsProxyKey;
			Botan::X509_Cert_Options options{};
			options.start = cert.not_before();
			options.end = cert.not_after();
			if (!cert.subject_info("X520.CommonName").empty()) {
				options.common_name = cert.subject_info("X520.CommonName").at(0);
			}
			if (!cert.subject_info("X520.Country").empty()) {
				options.country = cert.subject_info("X520.Country").at(0);
			}
			if (!cert.subject_info("X520.Organization").empty()) {
				options.organization = cert.subject_info("X520.Organization").at(0);
			}
			if (!cert.subject_info("X509.Certificate.serial").empty()) {
				options.serial_number = cert.subject_info("X509.Certificate.serial").at(0);
			}
			options.is_CA = false;
			options.constraints = cert.constraints();

			auto alternateSubjectNames = std::make_unique<Botan::Cert_Extension::Subject_Alternative_Name>();
			auto origSubjectAlternateNames = cert.v3_extensions().get(Botan::OID("2.5.29.17"));
			if (origSubjectAlternateNames) {
				options.extensions.add(origSubjectAlternateNames->copy());
			}

			auto certReq = Botan::X509::create_cert_req(options, *this->generatedKey, "SHA-256", rng);

			const Botan::X509_CA ca(caCert, *caKey, "SHA-256", rng);
			this->generatedCert = ca.sign_request(certReq, rng, cert.not_before(), cert.not_after());
			Logger::get().log("Generated cert: " + this->generatedCert.to_string());
			this->creds->caCert = std::make_shared<Botan::X509_Certificate>(caCert);
			this->creds->generatedCert = std::make_shared<Botan::X509_Certificate>(this->generatedCert);
			this->creds->generatedKey = this->generatedKey;
		}

		[[nodiscard]] std::shared_ptr<Botan::TLS::Server>& getServer() {
			return server;
		}
};
