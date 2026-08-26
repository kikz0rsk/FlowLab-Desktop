#include "tls_processor.h"

#include <botan/certstor.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/tls_alert.h>
#include <botan/tls_client.h>

#include <boost/asio.hpp>

#include <botan/tls_server.h>

#include "client.h"
#include "client_forwarder.h"
#include "connection_manager.h"
#include "logger.h"
#include "processor_context.h"
#include "server_forwarder.h"
#include "tcp_connection.h"
#include "pcapplusplus/Layer.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/SSLLayer.h"
#include "pcapplusplus/SystemUtils.h"

TlsProcessor::TlsProcessor() {
}

void TlsProcessor::init(const ProcessorInitContext& ctx) {
	this->conn = std::weak_ptr(std::dynamic_pointer_cast<TcpConnection>(ctx.connection));
	this->state = {};
}

std::vector<uint8_t> TlsProcessor::processDataToSocket(std::span<const uint8_t> data, ProcessorRuntimeContext &context, NextForwarderCallback next) {
	if (!pcpp::SSLLayer::isSSLPort(context.connection->getDstPort())) {
		// if not TLS/SSL, pass through unchanged
		return next(data);
	}

	context.meta[META_TLS_RELAY] = "1";
	auto& handshakeBuffer = this->state.tlsHandshakeBuffer;

	if (this->state.ready) {
		// just forward the data
		if (!handshakeBuffer.empty()) {
			this->state.serverTlsForwarder->getServer()->received_data(std::span(handshakeBuffer));
			handshakeBuffer.clear();
		}
		// populates `tlsServerInputBuffer`
		this->state.serverTlsForwarder->getServer()->received_data(data);

		const auto decryptedData = takeBuffer(this->state.tlsServerInputBuffer);
		const auto newData = next(std::span(decryptedData));

		// populates `tlsClientOutputBuffer`
		this->state.clientTlsForwarder->getClient()->send(newData);

		return takeBuffer(this->state.tlsClientOutputBuffer);
	}

	// init the tls forwarder
	if (const auto* sslLayer = dynamic_cast<pcpp::SSLHandshakeLayer *>(context.origPacket->getNextLayer()->getNextLayer())) {
		this->state.clientHandshakeRecordSize = pcpp::netToHost16(sslLayer->getRecordLayer()->length);
	}
	handshakeBuffer.insert(handshakeBuffer.end(), data.begin(), data.end());
	if (handshakeBuffer.size() >= this->state.clientHandshakeRecordSize) {
		pcpp::Packet dummyPacket;
		const pcpp::SSLHandshakeLayer sslHandshakeLayer(handshakeBuffer.data(), handshakeBuffer.size(), nullptr, &dummyPacket);
		if (const auto* clientHello = sslHandshakeLayer.getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>()) {
			if (const auto* sniExt = dynamic_cast<pcpp::SSLServerNameIndicationExtension *>(clientHello->getExtensionOfType(pcpp::SSL_EXT_SERVER_NAME)); sniExt != nullptr) {
				auto& sni = this->state.serverNameIndication;
				sni = sniExt->getHostName();
				if (!sni.empty()) {
					this->state.domains.emplace_back(sni);
				}
			}
		}
		initTlsClient(context.connection->getDstPort());
		if (auto client = context.connection->getClient(); client) {
			client->getConnectionManager()->markAsTlsConnection(std::dynamic_pointer_cast<TcpConnection>(context.connection));
		}
	}

	return {};
}

std::vector<uint8_t> TlsProcessor::processDataToDevice(std::span<const uint8_t> data, ProcessorRuntimeContext &context, NextForwarderCallback next) {
	if (!pcpp::SSLLayer::isSSLPort(context.connection->getDstPort())) {
		// if not TLS/SSL, pass through unchanged
		return next(data);
	}

	context.meta[META_TLS_RELAY] = "1";
	// populates `tlsClientInputBuffer`
	this->state.clientTlsForwarder->getClient()->received_data(data);
	const auto decryptedData = takeBuffer(this->state.tlsClientInputBuffer);
	const auto newData = next(std::span(decryptedData));

	// populates `tlsServerOutputBuffer`
	this->state.serverTlsForwarder->getServer()->send(newData);
	return takeBuffer(this->state.tlsServerOutputBuffer);
}

std::string TlsProcessor::getServerNameIndication() const {
	return this->state.serverNameIndication;
}

std::string TlsProcessor::getTlsRelayStatus() const {
	return this->state.tlsRelayStatus;
}

std::vector<std::string> TlsProcessor::getDomains() const {
	return this->state.domains;
}

const TlsProcessor::State & TlsProcessor::getState() const {
	return this->state;
}

void TlsProcessor::onTlsClientDataToSend(std::span<const uint8_t> data) {
	Logger::get().log("[TLS Proxy Client] Sending " + std::to_string(data.size()) + " bytes to remote");

	this->state.tlsClientOutputBuffer.insert(this->state.tlsClientOutputBuffer.end(), data.begin(), data.end());
}

void TlsProcessor::onTlsClientDataReceived(std::span<const uint8_t> data) {
	Logger::get().log("[TLS Proxy Client] Received " + std::to_string(data.size()) + " bytes from remote");

	this->state.tlsClientInputBuffer.insert(this->state.tlsClientInputBuffer.end(), data.begin(), data.end());
}

void TlsProcessor::onTlsClientAlert(Botan::TLS::Alert alert) {
	if (const auto connPtr = this->conn.lock(); connPtr) {
		connPtr->log(this->state.serverNameIndication + " TLS Client alert: " + alert.type_string());
	}
	if (alert.is_fatal()) {
		this->state.tlsRelayStatus = "Remote Fail: " + alert.type_string();
	}

	if (this->state.serverTlsForwarder && this->state.serverTlsForwarder->getServer()) {
		this->state.serverTlsForwarder->getServer()->send_alert(alert);
	}
}

void TlsProcessor::onTlsClientGotCertificate(const Botan::X509_Certificate &cert) {
	Logger::get().log("Received certificate: " + cert.to_string());
	this->initTlsServer(cert);
	this->state.tlsRelayStatus = "Received certificate";
	if (!cert.subject_info("X520.CommonName").empty()) {
		for (const auto& domain : cert.subject_info("X520.CommonName")) {
			if (domain.empty()) {
				continue;
			}
			this->state.domains.emplace_back(domain);
		}
	}
	const auto& altName = cert.subject_alt_name();
	if (altName.has_items() && !altName.dn().to_string().empty()) {
		this->state.domains.emplace_back(altName.dn().to_string());
	}

	this->state.ready = true;
	auto& tlsHandshakeBuffer = this->state.tlsHandshakeBuffer;
	if (!tlsHandshakeBuffer.empty()) {
		const std::vector data(tlsHandshakeBuffer.begin(), tlsHandshakeBuffer.end());
		this->state.serverTlsForwarder->getServer()->received_data(data);
		tlsHandshakeBuffer.clear();
	}
}

void TlsProcessor::onTlsServerDataReceived(std::span<const uint8_t> data) {
	Logger::get().log("[TLS Proxy Server] Received " + std::to_string(data.size()) + " bytes from client");

	this->state.tlsServerInputBuffer.insert(this->state.tlsServerInputBuffer.end(), data.begin(), data.end());
}

void TlsProcessor::onTlsServerDataToSend(std::span<const uint8_t> data) {
	Logger::get().log("[TLS Proxy Server] Sending " + std::to_string(data.size()) + " bytes to client");
	this->state.tlsServerOutputBuffer.insert(this->state.tlsServerOutputBuffer.end(), data.begin(), data.end());
}

void TlsProcessor::onTlsServerAlert(Botan::TLS::Alert alert) {
	if (const auto connPtr = this->conn.lock(); connPtr) {
		connPtr->log(this->state.serverNameIndication + " TLS Server alert: " + alert.type_string());
	}
	if (alert.is_fatal()) {
		this->state.tlsRelayStatus = "Device Fail: " + alert.type_string();
	}
	if (this->state.clientTlsForwarder && this->state.clientTlsForwarder->getClient()) {
		this->state.clientTlsForwarder->getClient()->send_alert(alert);
	}
}

void TlsProcessor::onTlsServerSuccess() {
}

void TlsProcessor::initTlsClient(uint16_t dstPort) {
	this->state.clientTlsForwarder = std::make_shared<ClientForwarder>(
		this->state.serverNameIndication,
		dstPort,
		[this](uint64_t seq_no, std::span<const uint8_t> data) {
			this->onTlsClientDataReceived(data);
		},
		[this](std::span<const uint8_t> data) {
			this->onTlsClientDataToSend(data);
		},
		[this](Botan::TLS::Alert alert) {
			this->onTlsClientAlert(alert);
		},
		[this](const Botan::X509_Certificate &cert) {
			this->onTlsClientGotCertificate(cert);
		}
	);
}

void TlsProcessor::initTlsServer(const Botan::X509_Certificate &cert) {
	this->state.serverTlsForwarder = std::make_shared<ServerForwarder>(
		cert,
		[this](uint64_t seq_no, std::span<const uint8_t> data) {
			this->onTlsServerDataReceived(data);
		},
		[this](std::span<const uint8_t> data) {
			this->onTlsServerDataToSend(data);
		},
		[this](Botan::TLS::Alert alert) {
			this->onTlsServerAlert(alert);
		},
		[this] {
			this->onTlsServerSuccess();
		}
	);
}

std::vector<uint8_t> TlsProcessor::takeBuffer(std::vector<uint8_t> &buffer) {
	return std::exchange(buffer, {});
}
