#include <memory>
#include <botan/auto_rng.h>
#include <botan/tls.h>

#include "forwarder.h"
#include "logger.h"

Forwarder::Forwarder(SOCKET socket) : socket(socket) {}

SimpleForwarder::SimpleForwarder(SOCKET socket) : Forwarder(socket) {}

void TlsForwarder::Callbacks::tls_emit_data(std::span<const uint8_t> data) {
	::send(forwarder.socket, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0);
}

void TlsForwarder::Callbacks::tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) {
	// process full TLS record received by tls server, e.g.,
	// by passing it to the application
	BOTAN_UNUSED(seq_no, data);
}

void TlsForwarder::Callbacks::tls_alert(Botan::TLS::Alert alert) {
	// handle a tls alert received from the tls server
	BOTAN_UNUSED(alert);
}

void SimpleForwarder::send(std::vector<uint8_t> &data) {
	::send(socket, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0);
}

TlsForwarder::TlsForwarder(SOCKET socket) : Forwarder(socket) {
	using namespace Botan;
	auto callbacks = std::make_shared<Callbacks>(*this);
	auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
	auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
	auto creds = std::make_shared<ClientCredentials>(*this);
	auto policy = std::make_shared<Botan::TLS::Strict_Policy>();

	client = std::make_shared<Botan::TLS::Client>(callbacks,
							  session_mgr,
							  creds,
							  policy,
							  rng,
							  Botan::TLS::Server_Information("", 443),
							  Botan::TLS::Protocol_Version::TLS_V12);
	Logger::get().log("TLS forwarder created");
}

void TlsForwarder::send(std::vector<uint8_t> &data) {
	client->send(data);
}
