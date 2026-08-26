#pragma once

#include <optional>
#include <fstream>

#include "iprocessor.h"
#include "processor_context.h"
#include "tls_processor.h"

class TlsProcessor;

class LogProcessor : public IProcessor {
	std::optional<std::ofstream> logFile;
	int lastLogDirection = 0;

	public:
		static constexpr const char *SERVER_TAG = "SERVER>>>>>>>>>";
		static constexpr const char *CLIENT_TAG = "CLIENT>>>>>>>>>";

		static constexpr int DRCTN_FROM_SERVER = 1;
		static constexpr int DRCTN_FROM_CLIENT = 2;

		LogProcessor() = default;
		~LogProcessor() override = default;

		std::vector<uint8_t> processDataToDevice(std::span<const uint8_t> data, ProcessorRuntimeContext& context, NextForwarderCallback next) override;
		std::vector<uint8_t> processDataToSocket(std::span<const uint8_t> data, ProcessorRuntimeContext& context, NextForwarderCallback next) override;

		void onRemoteConnectionChanged(RemoteSocketStatus oldStatus, RemoteSocketStatus newStatus) override;

	private:
		void tryInitFile(ProcessorRuntimeContext& context);
		void writeHeader(int direction, std::string_view tag);
		void writeFromServer(std::span<const uint8_t> data);
		void writeFromClient(std::span<const uint8_t> data);

		template<typename Callback>
		requires std::invocable<Callback>
		std::vector<uint8_t> logAndForward(std::span<const uint8_t> data, ProcessorRuntimeContext& context, NextForwarderCallback next, Callback logCallback) {
			if (!context.meta.contains(TlsProcessor::META_TLS_RELAY)) {
				return next(data);
			}

			tryInitFile(context);
			if (this->logFile.has_value()) {
				logCallback();
			}

			return next(data);
		}
};
