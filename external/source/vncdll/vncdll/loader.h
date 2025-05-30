//===============================================================================================//
#ifndef _VNCDLL_LOADER_LOADER_H
#define _VNCDLL_LOADER_LOADER_H
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <winuser.h>
#include <stdio.h>
#include <stdlib.h>

//#define DEBUGTRACE

#ifdef DEBUGTRACE
#define dprintf(...) real_dprintf(__VA_ARGS__)
static void real_dprintf(char *format, ...) {
	va_list args;
	char buffer[1024];
	FILE * fp = fopen("c:\\debug_log_loader.txt","a");
	va_start(args,format);
	vsnprintf_s(buffer, sizeof(buffer), sizeof(buffer)-3, format,args);
	strcat_s(buffer, sizeof(buffer), "\r\n\x00");
	if(fp)
	{
		fputs( buffer, fp );
		fclose(fp);
	}
	OutputDebugString(buffer);
}
#else
#define dprintf(...) do{}while(0);
#endif

// Simple macro to close a handle and set the handle to NULL.
#define CLOSE_HANDLE( h )	if( h ) { CloseHandle( h ); h = NULL; }

#define BREAK_ON_ERROR( str ) { dwResult = GetLastError(); dprintf( "%s. error=%d", str, dwResult ); break; }
#define BREAK_WITH_ERROR( str, err ) { dwResult = err; dprintf( "%s. error=%d", str, dwResult ); break; }
#define BREAK_ON_WSAERROR( str ) { dwResult = WSAGetLastError(); dprintf( "%s. error=%d", str, dwResult ); break; }

#define IDR_VNC_DLL		1

typedef DWORD (WINAPI * NTQUERYINFORMATIONPROCESS)( HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength );

//===============================================================================================//
#endif
//===============================================================================================//
