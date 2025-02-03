#pragma once

#include <exception>
#include <string>
#include <winsock2.h>

class SocketUtils {
	public:
		class EofException : public std::exception {
			public:
				const char * what() const noexcept override;
		};

		class SocketError : public std::exception {
			protected:
				int errorCode;
				std::string msg;
			public:
				SocketError(int errorCode);

				const char * what() const noexcept override;
		};

		static int readExactly(SOCKET socket, char *buffer, int length);
		static int writeExactly(SOCKET socket, const char *buffer, int length);
};
