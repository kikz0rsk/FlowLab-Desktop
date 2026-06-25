#pragma once

#include <cstdint>

struct TcpState {
	unsigned int ackNumber = 0;
	std::uint32_t ourSequenceNumber = 0;
	unsigned long long ourWindowSize = 65'535;
	unsigned long long remoteWindowSize = 65'535;
	unsigned int windowSizeMultiplier = 1;
	std::uint32_t finSequenceNumber = 0;
	unsigned long long unAckedBytes = 0;
	unsigned int lastRemoteAckedNum = 0;
	bool shouldSendFinOnAckedEverything = false;
};
