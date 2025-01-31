#include "socket_utils.h"

#include <string>

#include "logger.h"

int SocketUtils::readExactly(SOCKET socket, char *buffer, int length) {
	int currOffset = 0;
	while (currOffset < length) {
		const int bytesRead = recv(socket, buffer + currOffset, length - currOffset, 0);
		if (bytesRead == 0 || bytesRead == SOCKET_ERROR) {
			return bytesRead;
		}

		currOffset += bytesRead;
	}

	return length;
}

int SocketUtils::writeExactly(SOCKET socket, const char *buffer, int length) {
	int currOffset = 0;
	while (currOffset < length) {
		const int bytesWritten = send(socket, buffer + currOffset, length - currOffset, 0);
		if (bytesWritten == 0 || bytesWritten == SOCKET_ERROR) {
			return bytesWritten;
		}

		currOffset += bytesWritten;
	}

	return length;
}

