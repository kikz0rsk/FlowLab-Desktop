#pragma once
#include <functional>
#include <iostream>
#include <set>
#include <string>

class Logger {
public:
	using OnLogCallback = std::shared_ptr<std::function<void(const std::string &)>>;
protected:
	std::vector<std::string> logs;
	std::set<OnLogCallback> callbacks{};
	std::mutex mutex{};
public:
	virtual ~Logger() = default;

	Logger(const Logger &) = delete;
	Logger &operator=(const Logger &) = delete;

protected:
	Logger() {
		logs.reserve(100);
	};

public:
	static Logger& get() {
		static Logger logger{};
		return logger;
	}

	void log(const std::string &message) {
		std::lock_guard lock(mutex);
		logs.emplace_back(message);
		std::cout << message << std::endl;
		for (const auto &callback : callbacks) {
			callback->operator()(message);
		}
	}

	void registerEventCallback(const OnLogCallback &callback) {
		std::lock_guard lock(mutex);
		callbacks.emplace(callback);
	}

	void unregisterEventCallback(OnLogCallback callback) {
		std::lock_guard lock(mutex);
		for (auto it = callbacks.begin(); it != callbacks.end(); ++it) {
			if (*it == callback) {
				callbacks.erase(it);
				break;
			}
		}
	}
};
