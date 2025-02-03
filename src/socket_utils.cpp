#include "socket_utils.h"

const char * SocketUtils::EofException::what() const noexcept {
	return "End of file";
}

SocketUtils::SocketError::SocketError(int errorCode) : errorCode(errorCode), msg("Socket error: " + std::to_string(errorCode)) {}

const char * SocketUtils::SocketError::what() const noexcept {
	return msg.c_str();
}

int SocketUtils::readExactly(SOCKET socket, char *buffer, int length) {
	int currOffset = 0;
	while (currOffset < length) {
		const int bytesRead = recv(socket, buffer + currOffset, length - currOffset, 0);
		if (bytesRead == 0) {
			throw EofException();
		}
		if (bytesRead == SOCKET_ERROR) {
			const auto errCode = WSAGetLastError();
			if (errCode == WSAEWOULDBLOCK) {
				continue;
			}
			throw SocketError(WSAGetLastError());
		}

		currOffset += bytesRead;
	}

	return length;
}

int SocketUtils::writeExactly(SOCKET socket, const char *buffer, int length) {
	int currOffset = 0;
	while (currOffset < length) {
		const int bytesWritten = send(socket, buffer + currOffset, length - currOffset, 0);
		if (bytesWritten == 0) {
			throw EofException();
		}
		if (bytesWritten == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
			throw SocketError(WSAGetLastError());
		}

		currOffset += bytesWritten;
	}

	return length;
}
