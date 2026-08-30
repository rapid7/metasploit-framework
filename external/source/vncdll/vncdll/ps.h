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
