#pragma once

#include <botan/certstor.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/x509path.h>
#include <botan/tls_alert.h>
#include <botan/tls_client.h>
#include <botan/tls.h>
#include <botan/certstor_system.h>

class ClientForwarder {
	public:
		using DataReceivedCallback = std::function<void (uint64_t seq_no, std::span<const uint8_t> data)>;
		using DataReadyCallback = std::function<void (std::span<const uint8_t> data)>;
		using TlsAlertCallback = std::function<void (Botan::TLS::Alert alert)>;
		using CertificateNotifyCallback = std::function<void (const Botan::X509_Certificate &cert)>;

	protected:
		std::vector<std::string> domains;
		DataReceivedCallback dataReceivedCallback;
		DataReadyCallback dataReadyCallback;
		TlsAlertCallback tlsAlertCallback;
		CertificateNotifyCallback certificateNotifyCallback;
		std::shared_ptr<Botan::TLS::Client> client;
		std::string serverName;
		uint32_t serverPort;

	public:
		ClientForwarder(
			std::string serverName,
			uint16_t port,
			DataReceivedCallback dataReceivedCallback,
			DataReadyCallback dataReadyCallback,
			TlsAlertCallback tlsAlertCallback,
			CertificateNotifyCallback certificateNotifyCallback
		);

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
				);

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

		class ClientForwarderCredentials : public Botan::Credentials_Manager {
			protected:
				Botan::System_Certificate_Store caCertStore;

			public:
				explicit ClientForwarderCredentials();

				std::vector<Botan::Certificate_Store *> trusted_certificate_authorities(
					const std::string &type,
					const std::string &context
				) override;

				std::vector<Botan::X509_Certificate> cert_chain(
					const std::vector<std::string> &cert_key_types,
					const std::vector<Botan::AlgorithmIdentifier> &cert_signature_schemes,
					const std::string &type,
					const std::string &context
				) override;

				std::shared_ptr<Botan::Private_Key> private_key_for(
					const Botan::X509_Certificate &cert,
					const std::string &type,
					const std::string &context
				) override;
		};

		[[nodiscard]] std::shared_ptr<Botan::TLS::Client> & getClient() {
			return client;
		}
};
