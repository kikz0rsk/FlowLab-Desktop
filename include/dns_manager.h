#pragma once

#include "dns_entry.h"

#include <functional>
#include <vector>
#include <pcapplusplus/DnsLayer.h>

class DnsManager {
	public:
		using OnAddCallback = std::shared_ptr<std::function<void (const DnsEntry&)>>;

	private:
		std::vector<DnsEntry> dnsEntries;
		std::set<OnAddCallback> callbacks{};
		std::mutex mutex{};

	public:
		DnsManager() = default;

		void processDns(const pcpp::DnsLayer& layer);

		DnsEntry * getDnsEntry(const std::string &ip);

		DnsEntry& addDnsEntry(DnsEntry&& entry);

		void registerEventCallback(const OnAddCallback &callback);

		void unregisterEventCallback(OnAddCallback callback);
};
