#include "logger.h"

#include <iostream>

Logger & Logger::get() {
	static Logger logger{};

	return logger;
}

void Logger::log(const std::string &message) {
	std::lock_guard lock(mutex);
	// logs.emplace_back(message);
	std::cout << message << std::endl;
	for (const auto &callback : callbacks) {
		callback->operator()(message);
	}
}

void Logger::registerEventCallback(const OnLogCallback &callback) {
	std::lock_guard lock(mutex);
	callbacks.emplace(callback);
}

void Logger::unregisterEventCallback(OnLogCallback callback) {
	std::lock_guard lock(mutex);
	for (auto it = callbacks.begin(); it != callbacks.end(); ++it) {
		if (*it == callback) {
			callbacks.erase(it);
			break;
		}
	}
}
