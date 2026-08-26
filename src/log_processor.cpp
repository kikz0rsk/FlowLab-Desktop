#include "log_processor.h"

#include <format>
#include <regex>
#include <string>

#include "processor_context.h"
#include "tls_processor.h"

std::vector<uint8_t> LogProcessor::processDataToDevice(std::span<const uint8_t> data, ProcessorRuntimeContext &context, NextForwarderCallback next) {
	return logAndForward(data, context, next, [this, data] {
		this->writeFromServer(data);
	});
}

std::vector<uint8_t> LogProcessor::processDataToSocket(std::span<const uint8_t> data, ProcessorRuntimeContext &context, NextForwarderCallback next) {
	return logAndForward(data, context, next, [this, data] {
		this->writeFromClient(data);
	});
}

void LogProcessor::onRemoteConnectionChanged(RemoteSocketStatus oldStatus, RemoteSocketStatus newStatus) {
	if (newStatus == RemoteSocketStatus::CLOSED && this->logFile.has_value()) {
		this->logFile->close();
		this->logFile.reset();
	}
}

void LogProcessor::tryInitFile(ProcessorRuntimeContext &context) {
	if (this->logFile.has_value()) {
		return;
	}

	const std::shared_ptr<TlsProcessor> tlsProc = context.connection->getProcessor<TlsProcessor>();
	if (!tlsProc) {
		return;
	}

	const auto& conn = context.connection;
	std::string path = std::format(
		"tls-streams/{}_{}_{}.log",
		conn->getClient()->getClientIp().toString(),
		conn->getSrcPort(),
		tlsProc->getState().domains.empty() ? conn->getDstIp().toString() : tlsProc->getState().domains[0]
	);
	path = std::regex_replace(path, std::regex("(:|\\*)"), "_");
	this->logFile = std::ofstream(path);
}

void LogProcessor::writeHeader(int direction, std::string_view tag) {
	if (this->lastLogDirection != direction) {
		const std::string tagStr = std::format("\n{}\n", tag);
		this->logFile->write(tagStr.data(), static_cast<long long>(tagStr.size()));
	}
}

void LogProcessor::writeFromServer(std::span<const uint8_t> data) {
	// logFile check is in logAndForward
	writeHeader(DRCTN_FROM_SERVER, SERVER_TAG);
	this->logFile->write(reinterpret_cast<const char *>(data.data()), static_cast<long long>(data.size()));
}

void LogProcessor::writeFromClient(std::span<const uint8_t> data) {
	// logFile check is in logAndForward
	writeHeader(DRCTN_FROM_CLIENT, CLIENT_TAG);
	this->logFile->write(reinterpret_cast<const char *>(data.data()), static_cast<long long>(data.size()));
}
