#pragma once

#include <functional>
#include <set>
#include <vector>
#include <boost/signals2.hpp>
#include <pcapplusplus/DnsLayer.h>

struct DnsEntry;

class DnsManager {
	public:
		using OnAddCallback = std::shared_ptr<std::function<void (std::shared_ptr<DnsEntry>)>>;

	private:
		std::vector<std::shared_ptr<DnsEntry>> dnsEntries{};
		boost::signals2::signal<void (std::shared_ptr<DnsEntry>)> onAddSignal;
		std::mutex mutex{};

	public:
		DnsManager() = default;

		[[nodiscard]] boost::signals2::signal<void(std::shared_ptr<DnsEntry>)>& getOnAddSignal();

		void processDns(const pcpp::DnsLayer& layer);

		[[nodiscard]] std::shared_ptr<DnsEntry> getDnsEntry(const std::string &ip);

		std::shared_ptr<DnsEntry> addDnsEntry(DnsEntry &&entry);

		static std::string dnsTypeToString(pcpp::DnsType type);
};
