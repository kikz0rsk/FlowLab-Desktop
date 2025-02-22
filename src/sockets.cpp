#include "sockets.h"

int getLastSocketError() {
#ifdef _WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}

int initSockets() {
#ifdef _WIN32
	WSADATA wsaData;
	return WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
	return 0;
#endif
}

void cleanupSockets() {
#ifdef _WIN32
	WSACleanup();
#endif
}
