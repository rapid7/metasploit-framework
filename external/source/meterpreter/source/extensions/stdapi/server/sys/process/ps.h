//===============================================================================================//
#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_PROCESS_PS_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_PROCESS_PS_H
//===============================================================================================//

typedef DWORD (WINAPI * GETMODULEFILENAMEEXA)( HANDLE, HMODULE, LPTSTR, DWORD );
typedef HANDLE (WINAPI * CREATETOOLHELP32SNAPSHOT)( DWORD dwFlags, DWORD th32ProcessID );
typedef BOOL (WINAPI * PROCESS32FIRST)( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
typedef BOOL (WINAPI * PROCESS32NEXT)( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
typedef void (WINAPI * GETNATIVESYSTEMINFO)( LPSYSTEM_INFO lpSystemInfo );
typedef BOOL (WINAPI * ISWOW64PROCESS)( HANDLE hProcess, PBOOL Wow64Process );

typedef NTSTATUS (WINAPI * NTQUERYINFORMATIONPROCESS)( HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength );

typedef BOOL (WINAPI * ENUMPROCESSES)( DWORD * pProcessIds, DWORD cb, DWORD * pBytesReturned );
typedef BOOL (WINAPI * ENUMPROCESSMODULES)( HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded );
typedef DWORD (WINAPI * GETMODULEBASENAMEA)( HANDLE hProcess, HMODULE hModule, LPTSTR lpBaseName, DWORD nSize );

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

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StdInputHandle;
	HANDLE StdOutputHandle;
	HANDLE StdErrorHandle;
	_UNICODE_STRING CurrentDirectoryPath;
	HANDLE CurrentDirectoryHandle;
	_UNICODE_STRING DllPath;
	_UNICODE_STRING ImagePathName;
	_UNICODE_STRING CommandLine;
	//...
} RTL_USER_PROCESS_PARAMETERS, * LPRTL_USER_PROCESS_PARAMETERS;

//===============================================================================================//

DWORD ps_list_via_toolhelp( Packet * response );

DWORD ps_list_via_psapi( Packet * response );

DWORD ps_list_via_brute( Packet * response );

//===============================================================================================//
#endif
//===============================================================================================//