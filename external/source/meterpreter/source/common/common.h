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


// #define DEBUGTRACE

#ifdef DEBUGTRACE
#define dprintf(...) real_dprintf(__VA_ARGS__)
#else
#define dprintf(...) do{}while(0);
#endif




#ifdef _WIN32
static void real_dprintf(char *format, ...) {
	va_list args;
	char buffer[1024];
	va_start(args,format);
	vsnprintf_s(buffer, sizeof(buffer), sizeof(buffer)-3, format,args);
	strcat_s(buffer, sizeof(buffer), "\r\n");
	OutputDebugString(buffer);
}
#else
static void real_dprintf(char *format, ...) {
}
#endif

	

#endif
