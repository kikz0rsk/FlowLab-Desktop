#pragma once

enum class TcpStatus {
	CLOSED = 0,
	SYN_RECEIVED,
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSE_WAIT
};

constexpr std::array<std::string, 6> tcpStatusStrings = {
	"CLOSED",
	"SYN_RECEIVED",
	"ESTABLISHED",
	"FIN_WAIT_1",
	"FIN_WAIT_2",
	"CLOSE_WAIT"
};

inline std::string tcpStatusToString(TcpStatus status) {
	return tcpStatusStrings.at(static_cast<size_t>(status));
}

inline TcpStatus tcpStatusFromString(const std::string &status) {
	for (size_t i = 0; i < tcpStatusStrings.size(); ++i) {
		if (tcpStatusStrings[i] == status) {
			return static_cast<TcpStatus>(i);
		}
	}
	throw std::invalid_argument("Invalid TCP status string");
}