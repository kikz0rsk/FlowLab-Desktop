#pragma once

enum class RemoteSocketStatus {
	INITIATING,
	ESTABLISHED,
	CLOSED
};

const std::array<std::string, 3> remoteSocketStatusStrings = {
	"INITIATING",
	"ESTABLISHED",
	"CLOSED"
};

inline std::string remoteSocketStatusToString(RemoteSocketStatus status) {
	return remoteSocketStatusStrings.at(static_cast<size_t>(status));
}

inline RemoteSocketStatus remoteSocketStatusFromString(const std::string &status) {
	for (size_t i = 0; i < remoteSocketStatusStrings.size(); ++i) {
		if (remoteSocketStatusStrings[i] == status) {
			return static_cast<RemoteSocketStatus>(i);
		}
	}
	throw std::invalid_argument("Invalid remote socket status string");
}
