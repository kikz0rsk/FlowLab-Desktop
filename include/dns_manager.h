#pragma once

#include <functional>
#include <set>
#include <vector>
#include <pcapplusplus/DnsLayer.h>

struct DnsEntry;

class DnsManager {
	public:
		using OnAddCallback = std::shared_ptr<std::function<void (std::shared_ptr<DnsEntry>)>>;

	private:
		std::vector<std::shared_ptr<DnsEntry>> dnsEntries{};
		std::set<OnAddCallback> callbacks{};
		std::mutex mutex{};

	public:
		DnsManager() = default;

		void processDns(const pcpp::DnsLayer& layer);

		std::shared_ptr<DnsEntry> getDnsEntry(const std::string &ip);

		std::shared_ptr<DnsEntry> addDnsEntry(DnsEntry &&entry);

		void registerEventCallback(const OnAddCallback &callback);

		void unregisterEventCallback(OnAddCallback callback);

		static std::string dnsTypeToString(pcpp::DnsType type);
};
