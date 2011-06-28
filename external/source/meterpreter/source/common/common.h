#ifndef _METERPRETER_SOURCE_COMMON_COMMON_H
#define _METERPRETER_SOURCE_COMMON_COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
	#include <winsock2.h>
	#include <windows.h>
#endif
#include "openssl/ssl.h"
#ifdef _UNIX
#include "compat_types.h"

#include <fcntl.h>

#include <sys/select.h>
#include <sys/endian.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <sys/atomics.h>

struct ipv4_route_entry {
	__u32 dest;
	__u32 netmask;
	__u32 nexthop;
};

struct ipv4_routing_table {
	int entries;
	struct ipv4_route_entry routes[0];
};

int netlink_get_ipv4_routing_table(struct ipv4_routing_table **table);

extern int debugging_enabled;

#define dprintf(...) if(debugging_enabled) { real_dprintf(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); }

void real_dprintf(char *filename, int line, const char *function, char *format, ...);

#endif


#include "linkage.h"

#include "args.h"
#include "buffer.h"
#include "base.h"
#include "core.h"
#include "remote.h"

#include "channel.h"
#include "scheduler.h"
#include "thread.h"

#include "list.h"

#include "zlib/zlib.h"

#ifdef _WIN32

#include <wininet.h>

#define METERPRETER_TRANSPORT_SSL 0
#define METERPRETER_TRANSPORT_HTTP 1
#define METERPRETER_TRANSPORT_HTTPS 2

// Enable debugging
// #define DEBUGTRACE 1

#ifdef DEBUGTRACE
#define dprintf(...) real_dprintf(__VA_ARGS__)
#else
#define dprintf(...) do{}while(0);
#endif

#define BREAK_ON_ERROR( str ) { dwResult = GetLastError(); dprintf( "%s. error=%d", str, dwResult ); break; }
#define BREAK_WITH_ERROR( str, err ) { dwResult = err; dprintf( "%s. error=%d", str, dwResult ); break; }
#define BREAK_ON_WSAERROR( str ) { dwResult = WSAGetLastError(); dprintf( "%s. error=%d", str, dwResult ); break; }
#define CONTINUE_ON_ERROR( str ) { dwResult = GetLastError(); dprintf( "%s. error=%d", str, dwResult ); continue; }

// Simple macros to close a handle and set the handle to NULL.
#define CLOSE_SERVICE_HANDLE( h )	if( h ) { CloseServiceHandle( h ); h = NULL; }
#define CLOSE_HANDLE( h )			if( h ) { DWORD dwHandleFlags; if(GetHandleInformation( h , &dwHandleFlags)) CloseHandle( h ); h = NULL; }

static void real_dprintf(char *format, ...) {
	va_list args;
	char buffer[1024];
	va_start(args,format);
	vsnprintf_s(buffer, sizeof(buffer), sizeof(buffer)-3, format,args);
	strcat_s(buffer, sizeof(buffer), "\r\n");
	OutputDebugString(buffer);
}

#endif

#endif

int current_unix_timestamp(void);