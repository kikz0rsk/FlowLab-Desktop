#pragma once

enum class TcpStatus {
	CLOSED = 0,
	SYN_RECEIVED,
	FIN_SENT
};

constexpr std::array<std::string, 3> tcpStatusStrings = {
	"CLOSED",
	"SYN_RECEIVED",
	"FIN_SENT"
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