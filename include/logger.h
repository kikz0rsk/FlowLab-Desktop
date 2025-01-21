#pragma once

#include <functional>
#include <list>
#include <memory>
#include <set>
#include <string>

class Logger {
	public:
		using OnLogCallback = std::shared_ptr<std::function<void (const std::string &)>>;
	protected:
		std::list<std::string> logs;
		std::set<OnLogCallback> callbacks{};
		std::mutex mutex{};
	public:
		virtual ~Logger();

		Logger(const Logger &) = delete;
		Logger &operator=(const Logger &) = delete;

	protected:
		Logger();

	public:
		static Logger& get();

		void log(const std::string &message);

		void registerEventCallback(const OnLogCallback &callback);

		void unregisterEventCallback(OnLogCallback callback);
};
