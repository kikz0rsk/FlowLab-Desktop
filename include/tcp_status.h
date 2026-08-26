#pragma once

#include <array>
#include <string>
#include "remote_socket_status.h"

enum class TcpStatus {
	CLOSED = 0,
	SYN_RECEIVED,
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSE_WAIT
};

constexpr std::array<std::string, 6> TCP_STATUS_STRINGS = {
	"CLOSED",
	"SYN_RECEIVED",
	"ESTABLISHED",
	"FIN_WAIT_1",
	"FIN_WAIT_2",
	"CLOSE_WAIT"
};

inline std::string tcpStatusToString(TcpStatus status) {
	return TCP_STATUS_STRINGS.at(static_cast<size_t>(status));
}

inline TcpStatus tcpStatusFromString(const std::string &status) {
	for (size_t i = 0; i < TCP_STATUS_STRINGS.size(); ++i) {
		if (TCP_STATUS_STRINGS[i] == status) {
			return static_cast<TcpStatus>(i);
		}
	}
	throw std::invalid_argument("Invalid TCP status string");
}

inline RemoteSocketStatus tcpStatusToRemoteSocketStatus(TcpStatus tcpStatus) {
	RemoteSocketStatus status = RemoteSocketStatus::CLOSED;
	switch (tcpStatus) {
		case TcpStatus::SYN_RECEIVED:
			status = RemoteSocketStatus::INITIATING;
			break;
		case TcpStatus::ESTABLISHED:
		case TcpStatus::FIN_WAIT_1:
		case TcpStatus::FIN_WAIT_2:
		case TcpStatus::CLOSE_WAIT:
			status = RemoteSocketStatus::ESTABLISHED;
			break;
		case TcpStatus::CLOSED:
			status = RemoteSocketStatus::CLOSED;
			break;
	}

	return status;
}
