#pragma once

#include <vector>
#include <pcapplusplus/Packet.h>

struct OwnedParsedPacket {
	std::vector<uint8_t> buffer;
	pcpp::RawPacket rawPacket;
	pcpp::Packet packet;

	OwnedParsedPacket(std::vector<uint8_t> data, timeval ts, bool isIpv6)
			: buffer(std::move(data)),
				rawPacket(
						buffer.data(),
						static_cast<int>(buffer.size()),
						ts,
						false,
						isIpv6 ? pcpp::LINKTYPE_IPV6 : pcpp::LINKTYPE_IPV4
				),
				packet(&rawPacket) {}
};
