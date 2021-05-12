#pragma once

#include <windows.h>
#include <ntstatus.h>

#ifndef NTSTATUS
typedef long NTSTATUS;
#endif

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_table_entry.htm?ts=0,80
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT     UniqueProcessId;
	USHORT     CreatorBackTraceIndex;
	UCHAR	   ObjectTypeIndex;
	UCHAR      HandleAttributes;
	USHORT     HandleValue;
	PVOID      Object;
	ULONG      GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;
typedef SYSTEM_HANDLE_TABLE_ENTRY_INFO* PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[];
} SYSTEM_HANDLE_INFORMATION;
typedef SYSTEM_HANDLE_INFORMATION* PSYSTEM_HANDLE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS // this is an incomplete definition
{
	SystemBasicInformation = 0,                      // 3.10 and higher
	SystemProcessorInformation = 1,                  // 3.10 and higher
	SystemPerformanceInformation = 2,                // 3.10 and higher
	SystemTimeOfDayInformation = 3,                  // 3.10 and higher
	SystemPathInformation = 4,                       // 3.10 and higher
	SystemProcessInformation = 5,                    // 3.10 and higher
	SystemProcessorPerformanceInformation = 8,       // 3.10 and higher
	SystemFlagsInformation = 9,                      // 3.10 and higher
	SystemCallTimeInformation = 10,                  // 3.10 and higher
	SystemModuleInformation = 11,                    // 3.10 and higher
	SystemLocksInformation = 12,                     // 3.10 and higher
	SystemStackTraceInformation = 13,                // 3.10 and higher
	SystemPagedPoolInformation = 14,                 // 3.10 and higher
	SystemNonPagedPoolInformation = 15,              // 3.10 and higher
	SystemHandleInformation = 16,                    // 3.10 and higher
	SystemExceptionInformation = 33,                 // 3.50 and higher
	SystemRegistryQuotaInformation = 37,             // 3.51 and higher
	SystemLookasideInformation = 45,                 // 4.0 and higher
	SystemBigPoolInformation = 66,                   // 5.2 and higher
	SystemCodeIntegrityInformation = 103,            // 6.0 and higher
	SystemQueryPerformanceCounterInformation = 124,  // 6.1 and higher
	SystemKernelVaShadowInformation = 196,           // 1803 and higher
	SystemSpeculationControlInformation = 201,       // 1803 and higher
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(__stdcall* fNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef NTSTATUS(__stdcall* fNtCallbackReturn)(
	PVOID    Result,
	ULONG    ResultLength,
	NTSTATUS CallbackStateus
	);

typedef NTSTATUS(__stdcall* fNtUserConsoleControl)(
	DWORD ConsoleCtrl,
	PVOID ConsoleCtrlInfo,
	ULONG ConsoleCtrlInfoLength
	);

typedef VOID(__stdcall* fRtlGetNtVersionNumbers)(
	DWORD* MajorVersion,
	DWORD* MinorVersion,
	DWORD* BuildNumber
	);

#define TYPE_WINDOW 1
typedef PVOID(__stdcall* fHMValidateHandle)(HANDLE hHandle, DWORD dwType);
