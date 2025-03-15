#pragma once

#include <string>
#include <pcapplusplus/TcpLayer.h>

namespace pcpp {
	class Packet;
}

class PacketUtils {
	public:
		static std::string toString(const pcpp::Packet &packet);
};
