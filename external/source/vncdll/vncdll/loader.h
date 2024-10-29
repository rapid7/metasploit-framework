// Copyright (C) 2006-2010, Rapid7, Inc
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright notice,
//       this list of conditions and the following disclaimer in the documentation
//       and/or other materials provided with the distribution.
//
//     * Neither the name of Rapid7, Inc nor the names of its contributors
//       may be used to endorse or promote products derived from this software
//       without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
