#pragma once

#include <winsock2.h>

class SocketUtils {
  	public:
          static int readExactly(SOCKET socket, char *buffer, int length);
          static int writeExactly(SOCKET socket, const char *buffer, int length);
};