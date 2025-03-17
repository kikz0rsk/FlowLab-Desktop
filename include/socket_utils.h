#pragma once

#include <exception>
#include <string>
#include "sockets.h"

class SocketUtils {
	public:
		class EofException : public std::exception {
			public:
				[[nodiscard]] const char * what() const noexcept override;
		};

		class WouldBlockException : public std::exception {
			public:
				[[nodiscard]] const char * what() const noexcept override;
		};

		class SocketError : public std::exception {
			protected:
				int errorCode;
				std::string msg;
			public:
				explicit SocketError(int errorCode);

				[[nodiscard]] const char * what() const noexcept override;
		};

		static int write(SOCKET socket, const char *buffer, int length);
		static int read(SOCKET socket, char *buffer, int length);
		static int readExactly(SOCKET socket, char *buffer, int length);
		static int writeExactly(SOCKET socket, const char *buffer, int length);
		static int writeExactlyThrowBlock(SOCKET socket, const char *buffer, int length);
};
