#pragma once

#include <functional>
#include <span>
#include <cstdint>

#include "remote_socket_status.h"

struct ProcessorInitContext;
struct ProcessorRuntimeContext;
class Connection;

class IProcessor {
	public:
		using NextForwarderCallback = std::function<std::vector<uint8_t>(std::span<const uint8_t>)>;

		virtual ~IProcessor() = default;
		virtual void init(const ProcessorInitContext&) { }

		virtual std::vector<uint8_t> processDataToSocket(std::span<const uint8_t> data, ProcessorRuntimeContext &context, NextForwarderCallback next) {
			return next(data);
		}

		virtual std::vector<uint8_t> processDataToDevice(std::span<const uint8_t> data, ProcessorRuntimeContext &context, NextForwarderCallback next) {
			return next(data);
		}

		virtual void onClientConnectionChanged(RemoteSocketStatus /* oldStatus */, RemoteSocketStatus /* newStatus */) {}
		virtual void onRemoteConnectionChanged(RemoteSocketStatus /* oldStatus */, RemoteSocketStatus /* newStatus */) {}
};
