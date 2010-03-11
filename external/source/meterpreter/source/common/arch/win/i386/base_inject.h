//===============================================================================================//
#ifndef _METERPRETER_BASE_INJECT_H
#define _METERPRETER_BASE_INJECT_H
//===============================================================================================//

// These are defined in the stdapi projects ps.h file. We should put them somewhere more generic so we dont dup them here.
#define PROCESS_ARCH_UNKNOWN				0
#define PROCESS_ARCH_X86					1
#define PROCESS_ARCH_X64					2
#define PROCESS_ARCH_IA64					3

// The three injection techniques currently supported.
#define MIGRATE_TECHNIQUE_REMOTETHREAD		0
#define MIGRATE_TECHNIQUE_REMOTETHREADWOW64	1
#define MIGRATE_TECHNIQUE_APCQUEUE			2

//===============================================================================================//

// Definition of ntdll!NtQueueApcThread
typedef NTSTATUS (NTAPI * NTQUEUEAPCTHREAD)( HANDLE hThreadHandle, LPVOID lpApcRoutine, LPVOID lpApcRoutineContext, LPVOID lpApcStatusBlock, LPVOID lpApcReserved );

// Definitions used for running native x64 code from a wow64 process (see executex64.asm)
typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );
typedef DWORD (WINAPI * EXECUTEX64)( X64FUNCTION pFunction, DWORD dwParameter );

//===============================================================================================//

// The context used for injection via migrate_via_apcthread
typedef struct _APCCONTEXT
{
 	union
	{
		LPVOID lpStartAddress;
		BYTE bPadding1[8]; 
	} s;

	union
	{
 		LPVOID lpParameter;
		BYTE bPadding2[8];
	} p;

	BYTE bExecuted;

} APCCONTEXT, * LPAPCCONTEXT;

// The context used for injection via migrate_via_remotethread_wow64
typedef struct _WOW64CONTEXT
{
	union
	{
 		HANDLE hProcess;
		BYTE bPadding2[8];
	} h;

 	union
	{
		LPVOID lpStartAddress;
		BYTE bPadding1[8]; 
	} s;

	union
	{
 		LPVOID lpParameter;
		BYTE bPadding2[8];
	} p;
	union
	{
		HANDLE hThread;
		BYTE bPadding2[8];
	} t;
} WOW64CONTEXT, * LPWOW64CONTEXT;

//===============================================================================================//

DWORD inject_via_apcthread( Remote * remote, Packet * response, HANDLE hProcess, DWORD dwProcessID, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter );

DWORD inject_via_remotethread( Remote * remote, Packet * response, HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter );

DWORD inject_dll( DWORD dwPid, LPVOID lpDllBuffer, DWORD dwDllLenght, char * cpCommandLine );

//===============================================================================================//
#endif
//===============================================================================================//