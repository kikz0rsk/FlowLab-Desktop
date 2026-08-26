#pragma once

#include <memory>

#include "connection.h"

struct ProcessorInitContext {
	std::shared_ptr<Connection> connection;
};

struct ProcessorRuntimeContext {
	std::shared_ptr<Connection> connection;
	pcpp::Layer *origPacket = nullptr;
	boost::asio::io_context& ioContext;
	std::map<std::string, std::string, std::less<>> meta{};
};
