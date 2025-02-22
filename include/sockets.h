#pragma once

#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <unistd.h>
	#include <sys/ioctl.h>
	#define INVALID_SOCKET -1
	#define SOCKET_ERROR -1
	#define SD_BOTH SHUT_RDWR
	typedef int SOCKET;
	typedef const sockaddr SOCKADDR;

    #define WSAEINTR           EINTR         // Interrupted function call
    #define WSAEBADF           EBADF         // Bad file descriptor
    #define WSAEACCES          EACCES        // Permission denied
    #define WSAEFAULT          EFAULT        // Bad address
    #define WSAEINVAL          EINVAL        // Invalid argument
    #define WSAEMFILE          EMFILE        // Too many open files
    #define WSAEWOULDBLOCK     EWOULDBLOCK   // Operation would block
    #define WSAEINPROGRESS     EINPROGRESS   // Operation now in progress
    #define WSAEALREADY        EALREADY      // Operation already in progress
    #define WSAENOTSOCK        ENOTSOCK      // Socket operation on non-socket
    #define WSAEDESTADDRREQ    EDESTADDRREQ  // Destination address required
    #define WSAEMSGSIZE        EMSGSIZE      // Message too long
    #define WSAEPROTOTYPE      EPROTOTYPE    // Protocol wrong type for socket
    #define WSAENOPROTOOPT     ENOPROTOOPT   // Protocol not available
    #define WSAEPROTONOSUPPORT EPROTONOSUPPORT // Protocol not supported
    #define WSAESOCKTNOSUPPORT ESOCKTNOSUPPORT // Socket type not supported
    #define WSAEOPNOTSUPP      EOPNOTSUPP    // Operation not supported
    #define WSAEPFNOSUPPORT    EPFNOSUPPORT  // Protocol family not supported
    #define WSAEAFNOSUPPORT    EAFNOSUPPORT  // Address family not supported
    #define WSAEADDRINUSE      EADDRINUSE    // Address already in use
    #define WSAEADDRNOTAVAIL   EADDRNOTAVAIL // Cannot assign requested address
    #define WSAENETDOWN        ENETDOWN      // Network is down
    #define WSAENETUNREACH     ENETUNREACH   // Network is unreachable
    #define WSAENETRESET       ENETRESET     // Network dropped connection on reset
    #define WSAECONNABORTED    ECONNABORTED  // Software caused connection abort
    #define WSAECONNRESET      ECONNRESET    // Connection reset by peer
    #define WSAENOBUFS         ENOBUFS       // No buffer space available
    #define WSAEISCONN         EISCONN       // Socket is already connected
    #define WSAENOTCONN        ENOTCONN      // Socket is not connected
    #define WSAESHUTDOWN       ESHUTDOWN     // Cannot send after socket shutdown
    #define WSAETOOMANYREFS    ETOOMANYREFS  // Too many references
    #define WSAETIMEDOUT       ETIMEDOUT     // Connection timed out
    #define WSAECONNREFUSED    ECONNREFUSED  // Connection refused
    #define WSAELOOP           ELOOP         // Too many symbolic links
    #define WSAENAMETOOLONG    ENAMETOOLONG  // File name too long
    #define WSAEHOSTDOWN       EHOSTDOWN     // Host is down
    #define WSAEHOSTUNREACH    EHOSTUNREACH  // No route to host
#endif

int getLastSocketError();

int initSockets();
void cleanupSockets();
int closeSocket(SOCKET socket);
int ioctlSocket(SOCKET socket, long cmd, u_long *argp);
