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

int closeSocket(SOCKET socket) {
#ifdef WIN32
	return closesocket(socket);
#else
	return close(socket);
#endif
}

int ioctlSocket(SOCKET socket, long cmd, u_long *argp) {
#ifdef WIN32
	return ioctlsocket(socket, cmd, argp);
#else
	return ioctl(socket, cmd, argp);
#endif
}
