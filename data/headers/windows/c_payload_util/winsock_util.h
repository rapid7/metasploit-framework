#ifndef _WINSOCK_UTIL
#define _WINSOCK_UTIL

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <intrin.h>
#include <ws2tcpip.h>

typedef int (WINAPI *FuncWSAStartup)
(
  WORD wVersionRequired,
  LPWSADATA lpWSAData
);

typedef int (WINAPI *FuncWSACleanup) ();

typedef int (WINAPI *FuncGetAddrInfo)
(
  PCSTR pNodeName,
  PCSTR pServiceName,
  const ADDRINFO *pHints,
  LPADDRINFO *ppResult
);

typedef void (WINAPI *FuncFreeAddrInfo)
(
  LPADDRINFO pAddrInfo
);

typedef SOCKET (WINAPI *FuncWSASocketA) (
	int af,
	int type,
	int protocol,
	LPWSAPROTOCOL_INFO lpProtocolInfo,
	GROUP g,
	DWORD dwFlags
);

typedef int (WINAPI *FuncConnect)
(
  SOCKET s,
  const struct sockaddr *name,
  int namelen
);

typedef int (WINAPI *FuncSend)
(
  SOCKET s,
  const char *buf,
  int len,
  int flags
);

typedef int (WINAPI *FuncRecv)
(
  SOCKET s,
  char *buf,
  int len,
  int flags
);

#endif
