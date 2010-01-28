#ifndef _METERPRETER_SOURCE_ELEVATOR_ELEVATOR_H
#define _METERPRETER_SOURCE_ELEVATOR_ELEVATOR_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

//#define DEBUGTRACE

#ifdef DEBUGTRACE
#define dprintf(...) real_dprintf(__VA_ARGS__)
#else
#define dprintf(...) do{}while(0);
#endif

static void real_dprintf(char *format, ...) {
	va_list args;
	char buffer[1024];
	va_start(args,format);
	vsnprintf_s(buffer, sizeof(buffer), sizeof(buffer)-3, format,args);
	strcat_s(buffer, sizeof(buffer), "\r\n");
	OutputDebugString(buffer);
}

// Simple macro to close a handle and set the handle to NULL.
#define CLOSE_HANDLE( h )	if( h ) { CloseHandle( h ); h = NULL; }

#define BREAK_ON_ERROR( str ) { dwResult = GetLastError(); dprintf( "%s. error=%d", str, dwResult ); break; }
#define BREAK_WITH_ERROR( str, err ) { dwResult = err; dprintf( "%s. error=%d", str, dwResult ); break; }

typedef BOOL (WINAPI * CHECKTOKENMEMBERSHIP)( HANDLE TokenHandle, PSID SidToCheck, PBOOL IsMember );
typedef HANDLE (WINAPI * OPENTHREAD)( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId );

#endif