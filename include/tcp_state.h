#pragma once

#include <cstdint>

struct TcpState {
	std::uint32_t ackNumber = 0;
	std::uint32_t seqNumber = 0;
	unsigned long long ourWindowSize = 65'535;
	unsigned long long remoteWindowSize = 65'535;
	unsigned int windowSizeMultiplier = 1;
	std::uint32_t finSeqNumber = 0;
	std::uint32_t unAckedBytes = 0;
	std::uint32_t lastRemoteAckedNum = 0;
	bool waitingAck = false;
};
