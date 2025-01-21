#pragma once

#include <string>
#include <set>

struct DnsEntry {
	std::string domain;
	std::set<std::string> answers;
	std::string country;

	explicit DnsEntry(std::string domain) : domain(std::move(domain)) {}
};
