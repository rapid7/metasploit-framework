// Copyright (C) 2006-2010, Rapid7 LLC
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
//     * Neither the name of Rapid7 LLC nor the names of its contributors
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
#ifndef _VNCDLL_LOADER_PS_H
#define _VNCDLL_LOADER_PS_H
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>

typedef HANDLE (WINAPI * CREATETOOLHELP32SNAPSHOT)( DWORD dwFlags, DWORD th32ProcessID );
typedef BOOL (WINAPI * PROCESS32FIRST)( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
typedef BOOL (WINAPI * PROCESS32NEXT)( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
typedef void (WINAPI * GETNATIVESYSTEMINFO)( LPSYSTEM_INFO lpSystemInfo );
typedef BOOL (WINAPI * ISWOW64PROCESS)( HANDLE hProcess, PBOOL Wow64Process );

#define PROCESS_ARCH_UNKNOWN	0
#define PROCESS_ARCH_X86		1
#define PROCESS_ARCH_X64		2
#define PROCESS_ARCH_IA64		3

//===============================================================================================//

typedef struct _PROCESS_BASIC_INFORMATION
{
    PVOID Reserved1;
	PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _DLL_BUFFER
{
	LPVOID lpPE32DllBuffer;
	DWORD  dwPE32DllLenght;
	LPVOID lpPE64DllBuffer;
	DWORD  dwPE64DllLenght;
} DLL_BUFFER;

//===============================================================================================//

DWORD ps_inject( DWORD dwPid, DLL_BUFFER * pDllBuffer );

DWORD ps_getarch( DWORD dwPid );

DWORD ps_getnativearch( VOID );

//===============================================================================================//
#endif
//===============================================================================================//