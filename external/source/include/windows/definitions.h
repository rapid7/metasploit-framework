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
	SystemCallCountInformation = 6,                  // 3.10 and higher
	SystemDeviceInformation = 7,                     // 3.10 and higher
	SystemProcessorPerformanceInformation = 8,       // 3.10 and higher
	SystemFlagsInformation = 9,                      // 3.10 and higher
	SystemCallTimeInformation = 10,                  // 3.10 and higher
	SystemModuleInformation = 11,                    // 3.10 and higher
	SystemLocksInformation = 12,                     // 3.10 and higher
	SystemStackTraceInformation = 13,                // 3.10 and higher
	SystemPagedPoolInformation = 14,                 // 3.10 and higher
	SystemNonPagedPoolInformation = 15,              // 3.10 and higher
	SystemHandleInformation = 16,                    // 3.10 and higher
	SystemObjectInformation = 17,                    // 3.10 and higher
	SystemPageFileInformation = 18,                  // 3.10 and higher
	SystemVdmInstemulInformation = 19,               // 3.10 and higher
	SystemVdmBopInformation = 20,                    // 3.10 and higher
	SystemFileCacheInformation = 21,                 // 3.10 and higher
	SystemPoolTagInformation = 22,                   // 3.50 and higher
	SystemInterruptInformation = 23,                 // 3.51 and higher
	SystemExceptionInformation = 33,                 // 3.50 and higher
	SystemRegistryQuotaInformation = 37,             // 3.51 and higher
	SystemLookasideInformation = 45,                 // 4.0 and higher
	SystemBigPoolInformation = 66,                   // 5.2 and higher
	SystemCodeIntegrityInformation = 103,            // 6.0 and higher
	SystemQueryPerformanceCounterInformation = 124,  // 6.1 and higher
	SystemPolicyInformation = 134,                   // 6.2 and higher, was known as SystemThrottleNotificationInformation in 6.2
	SystemKernelVaShadowInformation = 196,           // 1803 and higher
	SystemSpeculationControlInformation = 201,       // 1803 and higher
	SystemDmaGuardPolicyInformation = 202,           // 1803 and higher
	SystemEnclaveLaunchControlInformation = 203      // 1803 and higher
} SYSTEM_INFORMATION_CLASS;

// Definitions taken from https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ps/psquery/class.htm
typedef enum _THREADINFOCLASS {
	ThreadBasicInformation = 0x0,                    // All versions
	ThreadTimes = 0x1,                               // All versions
	ThreadPriority = 0x2,                            // All versions
	ThreadBasePriority = 0x3,                        // All versions
	ThreadAffinityMask = 0x4,                        // All versions
	ThreadImpersonationToken = 0x5,                  // All versions
	ThreadDescriptorTableEntry = 0x6,                // All versions
	ThreadEnableAlignmentFaultFixup = 0x7,           // All versions
	ThreadEventPair = 0x8,                           // 3.10 to 4.0
	ThreadEventPair_Reuseable = 0x8,                 // 5.0 and higher
	ThreadQuerySetWin32StartAddress = 0x9,           // All versions
	ThreadZeroTlsCell = 0x0A,                        // All versions minus 3.10 where it was 0xB
	ThreadPerformanceCount = 0x0B,                   // 3.51 and higher
	ThreadAmILastThread = 0x0C,                      // 3.51 and higher
	ThreadIdealProcessor = 0x0D,                     // 4.0 and higher
	ThreadPriorityBoost = 0x0E,                      // 4.0 and higher
	ThreadSetTlsArrayAddress = 0x0F,                 // 4.0 and higher
	ThreadIsIoPending = 0x10,                        // 5.0 and higher
	ThreadHideFromDebugger = 0x11,                   // 5.0 and higher
	ThreadBreakOnTermination = 0x12,                 // 5.2 and higher
	ThreadSwitchLegacyState = 0x13,                  // 5.2 and higher from Windows Server 2003 SP1
	ThreadIsTerminated = 0x14,                       // 5.2 and higher from Windows Server 2003 SP1
	ThreadLastSystemCall = 0x15,                     // 6.0 and higher
	ThreadIoPriority = 0x16,                         // 6.0 and higher
	ThreadCycleTime = 0x17,                          // 6.0 and higher
	ThreadPagePriority = 0x18,                       // 6.0 and higher
	ThreadActualBasePriority = 0x19,                 // 6.0 and higher
	ThreadTebInformation = 0x1A,                     // 6.0 and higher
	ThreadCSwitchMon = 0x1B,                         // 6.0 and higher
	ThreadCSwitchPmu = 0x1C,                         // 6.1 and higher
	ThreadWow64Context = 0x1D,                       // 6.1 and higher
	ThreadGroupInformation = 0x1E,                   // 6.1 and higher
	ThreadUmsInformation = 0x1F,                     // 6.1 and higher
	ThreadCounterProfiling = 0x20,                   // 6.1 and higher
	ThreadIdealProcessorEx = 0x21,                   // 6.1 and higher
	ThreadCpuAccountingInformation = 0x22,           // 6.2 and higher
	ThreadSuspendCount = 0x23,                       // 6.3 and higher
	ThreadHeterogeneousCpuPolicy = 0x24,             // 10.0 and higher
	ThreadContainerId = 0x25,                        // 10.0 and higher
	ThreadNameInformation = 0x26,                    // 10.0 and higher
	ThreadSelectedCpuSets = 0x27,                    // 10.0 and higher
	ThreadSystemThreadInformation = 0x28,            // 10.0 and higher
	ThreadActualGroupAffinity = 0x29                 // 10.0 and higher
} THREADINFOCLASS;

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

typedef NTSTATUS(__stdcall* fNtUserMessageCall)(
	HWND hWnd,
	UINT msg,
	WPARAM wParam,
	LPARAM lParam,
	ULONG_PTR ResultInfo,
	DWORD dwType,
	BOOL bAscii
	);

typedef PVOID(__stdcall* fRtlAllocateHeap)(
	PVOID HeapHandle,
	ULONG Flags,
	SIZE_T Size
	);

typedef VOID(__stdcall* fRtlGetNtVersionNumbers)(
	DWORD* MajorVersion,
	DWORD* MinorVersion,
	DWORD* BuildNumber
	);

#define TYPE_WINDOW 1
typedef PVOID(__stdcall* fHMValidateHandle)(HANDLE hHandle, DWORD dwType);
