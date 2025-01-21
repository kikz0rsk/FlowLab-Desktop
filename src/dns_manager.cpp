#include "dns_manager.h"

DnsEntry& DnsManager::addDnsEntry(DnsEntry&& entry) {
	auto& res = this->dnsEntries.emplace_back(std::forward<DnsEntry>(entry));
	for (const auto &callback : callbacks) {
		callback->operator()(res);
	}

	return res;
}

void DnsManager::registerEventCallback(const OnAddCallback &callback) {
	std::lock_guard lock(mutex);
	callbacks.emplace(callback);
}

void DnsManager::unregisterEventCallback(OnAddCallback callback) {
	std::lock_guard lock(mutex);
	for (auto it = callbacks.begin(); it != callbacks.end(); ++it) {
		if (*it == callback) {
			callbacks.erase(it);
			break;
		}
	}
}

void DnsManager::processDns(const pcpp::DnsLayer& layer) {
	pcpp::DnsResource *dnsQuery = layer.getFirstAnswer();
	while (dnsQuery != nullptr) {
		const auto dnsQueryName = dnsQuery->getName();
		auto dnsEntryPtr = getDnsEntry(dnsQueryName);
		if (!dnsEntryPtr) {
			dnsEntryPtr = &addDnsEntry(DnsEntry(dnsQueryName));
		}

		DnsEntry& dnsEntry = *dnsEntryPtr;
		const std::string dnsResponseDataStr = dnsQuery->getData()->toString();
		if (!dnsEntry.answers.contains(dnsResponseDataStr)) {
			dnsEntry.answers.insert(dnsResponseDataStr);
		}

		dnsQuery = layer.getNextAnswer(dnsQuery);
	}
}

DnsEntry * DnsManager::getDnsEntry(const std::string &domain) {
	for (auto& entry: this->dnsEntries) {
		if (entry.domain == domain) {
			return &entry;
		}
	}

	return {};
}
