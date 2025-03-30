#include "dns_manager.h"

#include "dns_entry.h"
#include "logger.h"

std::shared_ptr<DnsEntry> DnsManager::addDnsEntry(DnsEntry &&entry) {
	auto res = this->dnsEntries.emplace_back(std::make_shared<DnsEntry>(std::forward<DnsEntry>(entry)));
	this->onAddSignal(res);

	return res;
}

std::string DnsManager::dnsTypeToString(pcpp::DnsType type) {
	switch (type) {
		case pcpp::DNS_TYPE_A:
			return "A";
		case pcpp::DNS_TYPE_NS:
			return "NS";
		case pcpp::DNS_TYPE_CNAME:
			return "CNAME";
		case pcpp::DNS_TYPE_SOA:
			return "SOA";
		case pcpp::DNS_TYPE_PTR:
			return "PTR";
		case pcpp::DNS_TYPE_MX:
			return "MX";
		case pcpp::DNS_TYPE_AAAA:
			return "AAAA";
		case pcpp::DNS_TYPE_SRV:
			return "SRV";
		case pcpp::DNS_TYPE_TXT:
			return "TXT";
		default:
			return "OTHER";
	}
}

boost::signals2::signal<void(std::shared_ptr<DnsEntry>)> & DnsManager::getOnAddSignal() {
	return onAddSignal;
}

void DnsManager::processDns(const pcpp::DnsLayer& layer) {
	Logger::get().log("calling processDns");
	pcpp::DnsResource *dnsQuery = layer.getFirstAnswer();
	while (dnsQuery != nullptr) {
		const auto dnsQueryName = dnsQuery->getName();
		auto dnsEntryPtr = getDnsEntry(dnsQueryName);
		if (!dnsEntryPtr) {
			dnsEntryPtr = addDnsEntry(DnsEntry(dnsQueryName));
		}

		DnsEntry& dnsEntry = *dnsEntryPtr;
		const std::string dnsResponseDataStr = dnsTypeToString(dnsQuery->getDnsType()) + ": " + dnsQuery->getData()->toString();
		if (!dnsEntry.answers.contains(dnsResponseDataStr)) {
			dnsEntry.answers.insert(dnsResponseDataStr);
		}

		dnsQuery = layer.getNextAnswer(dnsQuery);
	}
}

std::shared_ptr<DnsEntry> DnsManager::getDnsEntry(const std::string &domain) {
	for (auto& entry: this->dnsEntries) {
		if (entry->domain == domain) {
			return entry;
		}
	}

	return {};
}
