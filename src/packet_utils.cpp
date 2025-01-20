#include "packet_utils.h"

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/SystemUtils.h>

std::string PacketUtils::toString(const pcpp::Packet &packet) {
	std::string result = packet.toString();
	result.pop_back();

	if (auto tcpLayer = dynamic_cast<pcpp::TcpLayer *>(packet.getFirstLayer()->getNextLayer())) {
		result += ", SEQ=" + std::to_string(pcpp::netToHost32(tcpLayer->getTcpHeader()->sequenceNumber))
				+ " ACK=" + std::to_string(pcpp::netToHost32(tcpLayer->getTcpHeader()->ackNumber));
	}

	return result;
}
