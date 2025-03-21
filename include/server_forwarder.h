#pragma once

#include <botan/certstor.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/x509self.h>
#include <botan/x509_ca.h>

#include "proxy_service.h"

class ServerForwarderCredentials : public Botan::Credentials_Manager {
	public:
		std::shared_ptr<Botan::Private_Key> generatedKey;
		std::shared_ptr<Botan::X509_Certificate> generatedCert;
		std::shared_ptr<Botan::X509_Certificate> caCert;

		ServerForwarderCredentials();

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

class ServerForwarder {
	public:
		using DataReceivedCallback = std::function<void (uint64_t seq_no, std::span<const uint8_t> data)>;
		using DataReadyCallback = std::function<void (std::span<const uint8_t> data)>;
		using TlsAlertCallback = std::function<void (Botan::TLS::Alert alert)>;
		using SuccessCallback = std::function<void ()>;

	protected:
		std::shared_ptr<Botan::TLS::Server> server;
		DataReceivedCallback dataReceivedCallback;
		DataReadyCallback dataReadyCallback;
		TlsAlertCallback tlsAlertCallback;
		SuccessCallback successCallback;
		Botan::X509_Certificate generatedCert;
		Botan::X509_Certificate originalCert;
		std::shared_ptr<Botan::Private_Key> generatedKey;
		Botan::X509_Certificate caCert;
		std::shared_ptr<Botan::Private_Key> caKey;
		std::shared_ptr<ServerForwarderCredentials> creds;

	public:
		ServerForwarder(
			const Botan::X509_Certificate& origCert,
			DataReceivedCallback dataReceivedCallback,
			DataReadyCallback dataReadyCallback,
			TlsAlertCallback tlsAlertCallback,
			SuccessCallback successCallback
		);

		class ServerForwarderCallbacks : public Botan::TLS::Callbacks {
			protected:
				DataReceivedCallback dataReceivedCallback;
				DataReadyCallback dataReadyCallback;
				TlsAlertCallback tlsAlertCallback;
				SuccessCallback successCallback;

			public:
				explicit ServerForwarderCallbacks(
					DataReceivedCallback dataReceivedCallback,
					DataReadyCallback dataReadyCallback,
					TlsAlertCallback tlsAlertCallback,
					SuccessCallback successCallback
				);

				void tls_emit_data(std::span<const uint8_t> data) override;

				void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override;

				void tls_alert(Botan::TLS::Alert alert) override;

				void tls_session_activated() override;
		};

		[[nodiscard]] std::shared_ptr<Botan::TLS::Server>& getServer() {
			return server;
		}
};
