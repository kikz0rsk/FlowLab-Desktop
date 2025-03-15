#pragma once

#include <vector>
#include <cstdint>
#include <botan/tls.h>
#include <botan/certstor_system.h>

#include "sockets.h"

class Forwarder {
	protected:
		SOCKET socket;

	public:
		virtual ~Forwarder() = default;
		explicit Forwarder(SOCKET socket);

		virtual void send(std::vector<uint8_t> &data) = 0;
};

class SimpleForwarder : public Forwarder {
	public:
		void send(std::vector<uint8_t> &data) override;
		explicit SimpleForwarder(SOCKET socket);
};

class TlsForwarder : public Forwarder {
	public:
		std::string hostname;
		std::shared_ptr<Botan::TLS::Client> client;

	public:
		class Callbacks : public Botan::TLS::Callbacks {
			protected:
				TlsForwarder& forwarder;
			public:
				explicit Callbacks(TlsForwarder& forwarder) : forwarder(forwarder) {}

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
				) override {
					forwarder.hostname = std::string(hostname);
				}
		};

		class ClientCredentials : public Botan::Credentials_Manager {
			protected:
				TlsForwarder& forwarder;
				Botan::System_Certificate_Store m_cert_store;
			public:
				explicit ClientCredentials(TlsForwarder& forwarder) : forwarder(forwarder) {}

				std::vector<Botan::Certificate_Store *> trusted_certificate_authorities(
					const std::string& type,
					const std::string& context
				) override {
					return {&m_cert_store};
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
					// when returning a chain in cert_chain(), return the private key
					// associated with the leaf certificate here
					return nullptr;
				}
		};
		void send(std::vector<uint8_t> &data) override;
		explicit TlsForwarder(SOCKET socket);
};
