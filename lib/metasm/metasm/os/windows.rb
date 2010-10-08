#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/os/main'
require 'metasm/dynldr'

module Metasm
class WinAPI < DynLdr
	def self.api_not_found(lib, func)
		puts "could not find symbol #{func.inspect} in #{lib.inspect}" if $VERBOSE
	end

	new_api_c <<EOS, 'kernel32'
#line #{__LINE__}

typedef char CHAR;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int UINT;
typedef long LONG;
typedef unsigned long ULONG, DWORD, *LPDWORD;
typedef int BOOL;
typedef unsigned long long DWORD64, ULONGLONG;

typedef intptr_t INT_PTR, LONG_PTR;
typedef uintptr_t UINT_PTR, ULONG_PTR, DWORD_PTR, SIZE_T;
typedef LONG_PTR LPARAM;
typedef UINT_PTR WPARAM;
typedef LONG_PTR LRESULT;
typedef const CHAR *LPSTR, *LPCSTR;
typedef void VOID, *PVOID, *LPVOID;

typedef void *HANDLE;
typedef void *HMODULE;

#define DECLSPEC_IMPORT __declspec(dllimport)
#define WINUSERAPI DECLSPEC_IMPORT
#define WINBASEAPI DECLSPEC_IMPORT
#define WINAPI __stdcall
#define CALLBACK __stdcall
#define CONST const
#define ZEROOK __attribute__((zero_not_fail))
#define __in __attribute__((in))
#define __out __attribute__((out))
#define __opt __attribute__((opt))
#define __inout __in __out
#define __in_opt __in __opt
#define __out_opt __out __opt
#define __inout_opt __inout __opt

#define FORMAT_MESSAGE_FROM_SYSTEM     0x00001000
#define INFINITE            0xFFFFFFFF

#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define PAGE_GUARD            0x100
#define PAGE_NOCACHE          0x200
#define PAGE_WRITECOMBINE     0x400
#define MEM_COMMIT           0x1000
#define MEM_RESERVE          0x2000
#define MEM_DECOMMIT         0x4000
#define MEM_RELEASE          0x8000
#define MEM_FREE            0x10000
#define MEM_PRIVATE         0x20000
#define MEM_MAPPED          0x40000
#define MEM_RESET           0x80000
#define MEM_TOP_DOWN       0x100000
#define MEM_WRITE_WATCH    0x200000
#define MEM_PHYSICAL       0x400000
#define MEM_LARGE_PAGES  0x20000000
#define MEM_4MB_PAGES    0x80000000
#define SEC_FILE           0x800000
#define SEC_IMAGE         0x1000000
#define SEC_RESERVE       0x4000000
#define SEC_COMMIT        0x8000000
#define SEC_NOCACHE      0x10000000
#define SEC_LARGE_PAGES  0x80000000
#define MEM_IMAGE         SEC_IMAGE

#define DEBUG_PROCESS                     0x00000001
#define DEBUG_ONLY_THIS_PROCESS           0x00000002
#define CREATE_SUSPENDED                  0x00000004
#define DETACHED_PROCESS                  0x00000008
#define CREATE_NEW_CONSOLE                0x00000010
#define NORMAL_PRIORITY_CLASS             0x00000020
#define IDLE_PRIORITY_CLASS               0x00000040
#define HIGH_PRIORITY_CLASS               0x00000080
#define REALTIME_PRIORITY_CLASS           0x00000100
#define CREATE_NEW_PROCESS_GROUP          0x00000200
#define CREATE_UNICODE_ENVIRONMENT        0x00000400
#define CREATE_SEPARATE_WOW_VDM           0x00000800
#define CREATE_SHARED_WOW_VDM             0x00001000
#define CREATE_FORCEDOS                   0x00002000
#define BELOW_NORMAL_PRIORITY_CLASS       0x00004000
#define ABOVE_NORMAL_PRIORITY_CLASS       0x00008000
#define STACK_SIZE_PARAM_IS_A_RESERVATION 0x00010000
#define CREATE_BREAKAWAY_FROM_JOB         0x01000000
#define CREATE_PRESERVE_CODE_AUTHZ_LEVEL  0x02000000
#define CREATE_DEFAULT_ERROR_MODE         0x04000000
#define CREATE_NO_WINDOW                  0x08000000
#define PROFILE_USER                      0x10000000
#define PROFILE_KERNEL                    0x20000000
#define PROFILE_SERVER                    0x40000000
#define CREATE_IGNORE_SYSTEM_DEFAULT      0x80000000

#define STATUS_WAIT_0                    ((DWORD   )0x00000000L)
#define STATUS_ABANDONED_WAIT_0          ((DWORD   )0x00000080L)
#define STATUS_USER_APC                  ((DWORD   )0x000000C0L)
#define STATUS_TIMEOUT                   ((DWORD   )0x00000102L)
#define STATUS_PENDING                   ((DWORD   )0x00000103L)
#define DBG_EXCEPTION_HANDLED            ((DWORD   )0x00010001L)
#define DBG_CONTINUE                     ((DWORD   )0x00010002L)
#define STATUS_SEGMENT_NOTIFICATION      ((DWORD   )0x40000005L)
#define DBG_TERMINATE_THREAD             ((DWORD   )0x40010003L)
#define DBG_TERMINATE_PROCESS            ((DWORD   )0x40010004L)
#define DBG_CONTROL_C                    ((DWORD   )0x40010005L)
#define DBG_CONTROL_BREAK                ((DWORD   )0x40010008L)
#define DBG_COMMAND_EXCEPTION            ((DWORD   )0x40010009L)
#define STATUS_GUARD_PAGE_VIOLATION      ((DWORD   )0x80000001L)
#define STATUS_DATATYPE_MISALIGNMENT     ((DWORD   )0x80000002L)
#define STATUS_BREAKPOINT                ((DWORD   )0x80000003L)
#define STATUS_SINGLE_STEP               ((DWORD   )0x80000004L)
#define DBG_EXCEPTION_NOT_HANDLED        ((DWORD   )0x80010001L)
#define STATUS_ACCESS_VIOLATION          ((DWORD   )0xC0000005L)
#define STATUS_IN_PAGE_ERROR             ((DWORD   )0xC0000006L)
#define STATUS_INVALID_HANDLE            ((DWORD   )0xC0000008L)
#define STATUS_NO_MEMORY                 ((DWORD   )0xC0000017L)
#define STATUS_ILLEGAL_INSTRUCTION       ((DWORD   )0xC000001DL)
#define STATUS_NONCONTINUABLE_EXCEPTION  ((DWORD   )0xC0000025L)
#define STATUS_INVALID_DISPOSITION       ((DWORD   )0xC0000026L)
#define STATUS_ARRAY_BOUNDS_EXCEEDED     ((DWORD   )0xC000008CL)
#define STATUS_FLOAT_DENORMAL_OPERAND    ((DWORD   )0xC000008DL)
#define STATUS_FLOAT_DIVIDE_BY_ZERO      ((DWORD   )0xC000008EL)
#define STATUS_FLOAT_INEXACT_RESULT      ((DWORD   )0xC000008FL)
#define STATUS_FLOAT_INVALID_OPERATION   ((DWORD   )0xC0000090L)
#define STATUS_FLOAT_OVERFLOW            ((DWORD   )0xC0000091L)
#define STATUS_FLOAT_STACK_CHECK         ((DWORD   )0xC0000092L)
#define STATUS_FLOAT_UNDERFLOW           ((DWORD   )0xC0000093L)
#define STATUS_INTEGER_DIVIDE_BY_ZERO    ((DWORD   )0xC0000094L)
#define STATUS_INTEGER_OVERFLOW          ((DWORD   )0xC0000095L)
#define STATUS_PRIVILEGED_INSTRUCTION    ((DWORD   )0xC0000096L)
#define STATUS_STACK_OVERFLOW            ((DWORD   )0xC00000FDL)
#define STATUS_CONTROL_C_EXIT            ((DWORD   )0xC000013AL)
#define STATUS_FLOAT_MULTIPLE_FAULTS     ((DWORD   )0xC00002B4L)
#define STATUS_FLOAT_MULTIPLE_TRAPS      ((DWORD   )0xC00002B5L)
#define STATUS_REG_NAT_CONSUMPTION       ((DWORD   )0xC00002C9L)

#define EXCEPTION_DEBUG_EVENT       1
#define CREATE_THREAD_DEBUG_EVENT   2
#define CREATE_PROCESS_DEBUG_EVENT  3
#define EXIT_THREAD_DEBUG_EVENT     4
#define EXIT_PROCESS_DEBUG_EVENT    5
#define LOAD_DLL_DEBUG_EVENT        6
#define UNLOAD_DLL_DEBUG_EVENT      7
#define OUTPUT_DEBUG_STRING_EVENT   8
#define RIP_EVENT                   9

#define EXCEPTION_NONCONTINUABLE 0x1    // Noncontinuable exception
#define EXCEPTION_MAXIMUM_PARAMETERS 15 // maximum number of exception parameters

typedef struct _EXCEPTION_RECORD {
	DWORD ExceptionCode;
	DWORD ExceptionFlags;
	struct _EXCEPTION_RECORD *ExceptionRecord;
	PVOID ExceptionAddress;
	DWORD NumberParameters;
	ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

typedef struct _EXCEPTION_DEBUG_INFO {
	EXCEPTION_RECORD ExceptionRecord;
	DWORD dwFirstChance;
} EXCEPTION_DEBUG_INFO, *LPEXCEPTION_DEBUG_INFO;

typedef struct _CREATE_THREAD_DEBUG_INFO {
	HANDLE hThread;
	LPVOID lpThreadLocalBase;
	LPVOID lpStartAddress;
} CREATE_THREAD_DEBUG_INFO, *LPCREATE_THREAD_DEBUG_INFO;

typedef struct _CREATE_PROCESS_DEBUG_INFO {
	HANDLE hFile;
	HANDLE hProcess;
	HANDLE hThread;
	LPVOID lpBaseOfImage;
	DWORD  dwDebugInfoFileOffset;
	DWORD  nDebugInfoSize;
	LPVOID lpThreadLocalBase;
	LPVOID lpStartAddress;
	LPVOID lpImageName;
	WORD fUnicode;
} CREATE_PROCESS_DEBUG_INFO, *LPCREATE_PROCESS_DEBUG_INFO;

typedef struct _EXIT_THREAD_DEBUG_INFO {
	DWORD dwExitCode;
} EXIT_THREAD_DEBUG_INFO, *LPEXIT_THREAD_DEBUG_INFO;

typedef struct _EXIT_PROCESS_DEBUG_INFO {
	DWORD dwExitCode;
} EXIT_PROCESS_DEBUG_INFO, *LPEXIT_PROCESS_DEBUG_INFO;

typedef struct _LOAD_DLL_DEBUG_INFO {
	HANDLE hFile;
	LPVOID lpBaseOfDll;
	DWORD dwDebugInfoFileOffset;
	DWORD nDebugInfoSize;
	LPVOID lpImageName;
	WORD fUnicode;
} LOAD_DLL_DEBUG_INFO, *LPLOAD_DLL_DEBUG_INFO;

typedef struct _UNLOAD_DLL_DEBUG_INFO {
	LPVOID lpBaseOfDll;
} UNLOAD_DLL_DEBUG_INFO, *LPUNLOAD_DLL_DEBUG_INFO;

typedef struct _OUTPUT_DEBUG_STRING_INFO {
	LPSTR lpDebugStringData;
	WORD fUnicode;
	WORD nDebugStringLength;
} OUTPUT_DEBUG_STRING_INFO, *LPOUTPUT_DEBUG_STRING_INFO;

typedef struct _RIP_INFO {
	DWORD dwError;
	DWORD dwType;
} RIP_INFO, *LPRIP_INFO;

typedef struct _DEBUG_EVENT {
	DWORD dwDebugEventCode;
	DWORD dwProcessId;
	DWORD dwThreadId;
	union {
		EXCEPTION_DEBUG_INFO Exception;
		CREATE_THREAD_DEBUG_INFO CreateThread;
		CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
		EXIT_THREAD_DEBUG_INFO ExitThread;
		EXIT_PROCESS_DEBUG_INFO ExitProcess;
		LOAD_DLL_DEBUG_INFO LoadDll;
		UNLOAD_DLL_DEBUG_INFO UnloadDll;
		OUTPUT_DEBUG_STRING_INFO DebugString;
		RIP_INFO RipInfo;
	} u;
} DEBUG_EVENT, *LPDEBUG_EVENT;

#define CONTEXT_i386    0x00010000
#define CONTEXT86_CONTROL         (CONTEXT_i386 | 0x00000001L) // SS:SP, CS:IP, FLAGS, BP
#define CONTEXT86_INTEGER         (CONTEXT_i386 | 0x00000002L) // AX, BX, CX, DX, SI, DI
#define CONTEXT86_SEGMENTS        (CONTEXT_i386 | 0x00000004L) // DS, ES, FS, GS
#define CONTEXT86_FLOATING_POINT  (CONTEXT_i386 | 0x00000008L) // 387 state
#define CONTEXT86_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L) // DB 0-3,6,7
#define CONTEXT86_EXTENDED_REGISTERS  (CONTEXT_i386 | 0x00000020L) // cpu specific extensions

#define CONTEXT86_FULL (CONTEXT86_CONTROL | CONTEXT86_INTEGER | CONTEXT86_SEGMENTS)
#define CONTEXT86_ALL (CONTEXT86_FULL | CONTEXT86_FLOATING_POINT | CONTEXT86_DEBUG_REGISTERS | CONTEXT86_EXTENDED_REGISTERS)

#define MAXIMUM_SUPPORTED_EXTENSION     512
#define SIZE_OF_80387_REGISTERS      80

typedef struct _FLOATING_SAVE_AREA {
	DWORD   ControlWord;
	DWORD   StatusWord;
	DWORD   TagWord;
	DWORD   ErrorOffset;
	DWORD   ErrorSelector;
	DWORD   DataOffset;
	DWORD   DataSelector;
	BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];
	DWORD   Cr0NpxState;
} FLOATING_SAVE_AREA, *PFLOATING_SAVE_AREA;

typedef struct _CONTEXT {
	DWORD ContextFlags;
	DWORD   Dr0;
	DWORD   Dr1;
	DWORD   Dr2;
	DWORD   Dr3;
	DWORD   Dr6;
	DWORD   Dr7;
	FLOATING_SAVE_AREA FloatSave;
	DWORD   SegGs;
	DWORD   SegFs;
	DWORD   SegEs;
	DWORD   SegDs;
	DWORD   Edi;
	DWORD   Esi;
	DWORD   Ebx;
	DWORD   Edx;
	DWORD   Ecx;
	DWORD   Eax;
	DWORD   Ebp;
	DWORD   Eip;
	DWORD   SegCs;
	DWORD   EFlags;
	DWORD   Esp;
	DWORD   SegSs;
	BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT, *LPCONTEXT;


typedef struct _EXCEPTION_RECORD32 {
	DWORD ExceptionCode;
	DWORD ExceptionFlags;
	DWORD ExceptionRecord;
	DWORD ExceptionAddress;
	DWORD NumberParameters;
	DWORD ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD32, *PEXCEPTION_RECORD32;

typedef struct _EXCEPTION_RECORD64 {
	DWORD ExceptionCode;
	DWORD ExceptionFlags;
	DWORD64 ExceptionRecord;
	DWORD64 ExceptionAddress;
	DWORD NumberParameters;
	DWORD __unusedAlignment;
	DWORD64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD64, *PEXCEPTION_RECORD64;

typedef struct _EXCEPTION_POINTERS {
	PEXCEPTION_RECORD ExceptionRecord;
	LPCONTEXT ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

#define STANDARD_RIGHTS_REQUIRED         (0x000F0000L)
#define SYNCHRONIZE                      (0x00100000L)

#define PROCESS_TERMINATE         (0x0001)
#define PROCESS_CREATE_THREAD     (0x0002)
#define PROCESS_SET_SESSIONID     (0x0004)
#define PROCESS_VM_OPERATION      (0x0008)
#define PROCESS_VM_READ           (0x0010)
#define PROCESS_VM_WRITE          (0x0020)
#define PROCESS_DUP_HANDLE        (0x0040)
#define PROCESS_CREATE_PROCESS    (0x0080)
#define PROCESS_SET_QUOTA         (0x0100)
#define PROCESS_SET_INFORMATION   (0x0200)
#define PROCESS_QUERY_INFORMATION (0x0400)
#define PROCESS_SUSPEND_RESUME    (0x0800)
#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)

#define THREAD_TERMINATE               (0x0001)
#define THREAD_SUSPEND_RESUME          (0x0002)
#define THREAD_GET_CONTEXT             (0x0008)
#define THREAD_SET_CONTEXT             (0x0010)
#define THREAD_SET_INFORMATION         (0x0020)
#define THREAD_QUERY_INFORMATION       (0x0040)
#define THREAD_SET_THREAD_TOKEN        (0x0080)
#define THREAD_IMPERSONATE             (0x0100)
#define THREAD_DIRECT_IMPERSONATION    (0x0200)

typedef struct _STARTUPINFOA {
	DWORD   cb;
	LPSTR   lpReserved;
	LPSTR   lpDesktop;
	LPSTR   lpTitle;
	DWORD   dwX;
	DWORD   dwY;
	DWORD   dwXSize;
	DWORD   dwYSize;
	DWORD   dwXCountChars;
	DWORD   dwYCountChars;
	DWORD   dwFillAttribute;
	DWORD   dwFlags;
	WORD    wShowWindow;
	WORD    cbReserved2;
	LPVOID  lpReserved2;
	HANDLE  hStdInput;
	HANDLE  hStdOutput;
	HANDLE  hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;

typedef struct _PROCESS_INFORMATION {
	HANDLE hProcess;
	HANDLE hThread;
	DWORD dwProcessId;
	DWORD dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;


WINBASEAPI
HANDLE
WINAPI
OpenProcess(
	__in DWORD dwDesiredAccess,
	__in BOOL bInheritHandle,
	__in DWORD dwProcessId
);

WINBASEAPI
HANDLE
WINAPI
GetCurrentProcess(VOID);

WINBASEAPI
DWORD
WINAPI
GetCurrentProcessId(VOID);

WINBASEAPI
BOOL
WINAPI
TerminateProcess(
	__in HANDLE hProcess,
	__in UINT uExitCode);

WINBASEAPI
BOOL
WINAPI
GetExitCodeProcess(
	__in  HANDLE hProcess,
	__out LPDWORD lpExitCode);

WINBASEAPI
HANDLE
WINAPI
CreateRemoteThread(
	__in      HANDLE hProcess,
	__in_opt  LPVOID lpThreadAttributes,
	__in      DWORD dwStackSize,
	__in      LPVOID lpStartAddress,
	__in_opt  LPVOID lpParameter,
	__in      DWORD dwCreationFlags,
	__out_opt LPDWORD lpThreadId);

WINBASEAPI
DWORD
WINAPI
GetThreadId(
	__in HANDLE Thread);

WINBASEAPI
DWORD
WINAPI
GetProcessId(
	__in HANDLE Process);

WINBASEAPI
HANDLE
WINAPI
OpenThread(
	__in DWORD dwDesiredAccess,
	__in BOOL bInheritHandle,
	__in DWORD dwThreadId);

WINBASEAPI
BOOL
WINAPI
TerminateThread(
	__in HANDLE hThread,
	__in DWORD dwExitCode);

WINBASEAPI
BOOL
WINAPI
GetExitCodeThread(
	__in  HANDLE hThread,
	__out LPDWORD lpExitCode);

ZEROOK
WINBASEAPI
DWORD
WINAPI
GetLastError(VOID);

ZEROOK
WINBASEAPI
BOOL
WINAPI
ReadProcessMemory(
	__in      HANDLE hProcess,
	__in      LPVOID lpBaseAddress,
	__out     LPVOID lpBuffer,
	__in      DWORD nSize,
	__out_opt DWORD *lpNumberOfBytesRead);

WINBASEAPI
BOOL
WINAPI
WriteProcessMemory(
	__in      HANDLE hProcess,
	__in      LPVOID lpBaseAddress,
	__in      LPVOID lpBuffer,
	__in      DWORD nSize,
	__out_opt DWORD *lpNumberOfBytesWritten);

WINBASEAPI
BOOL
WINAPI
GetThreadContext(
	__in    HANDLE hThread,
	__inout LPCONTEXT lpContext);

WINBASEAPI
BOOL
WINAPI
SetThreadContext(
	__in HANDLE hThread,
	__in LPCONTEXT lpContext);

ZEROOK
WINBASEAPI
DWORD
WINAPI
SuspendThread(
	__in HANDLE hThread);

ZEROOK
WINBASEAPI
DWORD
WINAPI
ResumeThread(
	__in HANDLE hThread);

WINBASEAPI
VOID
WINAPI
DebugBreak(VOID);

ZEROOK
WINBASEAPI
BOOL
WINAPI
WaitForDebugEvent(
	__in LPDEBUG_EVENT lpDebugEvent,
	__in DWORD dwMilliseconds);

WINBASEAPI
BOOL
WINAPI
ContinueDebugEvent(
	__in DWORD dwProcessId,
	__in DWORD dwThreadId,
	__in DWORD dwContinueStatus);

WINBASEAPI
BOOL
WINAPI
DebugActiveProcess(
	__in DWORD dwProcessId);

WINBASEAPI
BOOL
WINAPI
DebugActiveProcessStop(
	__in DWORD dwProcessId);

WINBASEAPI
BOOL
WINAPI
DebugSetProcessKillOnExit(
	__in BOOL KillOnExit);

WINBASEAPI
BOOL
WINAPI
DebugBreakProcess (
	__in HANDLE Process);

ZEROOK
WINBASEAPI
DWORD
WINAPI
FormatMessageA(
	DWORD dwFlags,
	LPVOID lpSource,
	DWORD dwMessageId,
	DWORD dwLanguageId,
	LPSTR lpBuffer,
	DWORD nSize,
	LPVOID Arguments);

WINBASEAPI
BOOL
WINAPI
CreateProcessA(
	__in_opt    LPCSTR lpApplicationName,
	__inout_opt LPSTR lpCommandLine,
	__in_opt    LPVOID lpProcessAttributes,
	__in_opt    LPVOID lpThreadAttributes,
	__in        BOOL bInheritHandles,
	__in        DWORD dwCreationFlags,
	__in_opt    LPVOID lpEnvironment,
	__in_opt    LPCSTR lpCurrentDirectory,
	__in        LPSTARTUPINFOA lpStartupInfo,
	__out       LPPROCESS_INFORMATION lpProcessInformation);

WINBASEAPI
BOOL
WINAPI
CloseHandle(
	__in HANDLE hObject);

WINBASEAPI
LPVOID
WINAPI
VirtualAllocEx(
	__in     HANDLE hProcess,
	__in_opt LPVOID lpAddress,
	__in     SIZE_T dwSize,
	__in     DWORD flAllocationType,
	__in     DWORD flProtect);

WINBASEAPI
BOOL
WINAPI
VirtualFreeEx(
	__in HANDLE hProcess,
	__in LPVOID lpAddress,
	__in SIZE_T dwSize,
	__in DWORD  dwFreeType);

WINBASEAPI
BOOL
WINAPI
VirtualProtectEx(
	__in  HANDLE hProcess,
	__in  LPVOID lpAddress,
	__in  SIZE_T dwSize,
	__in  DWORD flNewProtect,
	__out LPDWORD lpflOldProtect);

#define TH32CS_SNAPHEAPLIST 0x00000001
#define TH32CS_SNAPPROCESS  0x00000002
#define TH32CS_SNAPTHREAD   0x00000004
#define TH32CS_SNAPMODULE   0x00000008
#define TH32CS_SNAPMODULE32 0x00000010
#define TH32CS_SNAPALL      (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
#define TH32CS_INHERIT      0x80000000

HANDLE
WINAPI
CreateToolhelp32Snapshot(
	DWORD dwFlags,
	DWORD th32ProcessID
);

typedef struct tagTHREADENTRY32
{
	DWORD   dwSize;
	DWORD   cntUsage;
	DWORD   th32ThreadID;       // this thread
	DWORD   th32OwnerProcessID; // Process this thread is associated with
	LONG    tpBasePri;
	LONG    tpDeltaPri;
	DWORD   dwFlags;
} THREADENTRY32, * LPTHREADENTRY32;

BOOL
WINAPI
Thread32First(
	HANDLE hSnapshot,
	LPTHREADENTRY32 lpte
);

BOOL
WINAPI
Thread32Next(
	HANDLE hSnapshot,
	LPTHREADENTRY32 lpte
);

typedef struct _MEMORY_BASIC_INFORMATION32 {
	DWORD BaseAddress;
	DWORD AllocationBase;
	DWORD AllocationProtect;	// initial (alloc time) prot
	DWORD RegionSize;
	DWORD State;	// MEM_FREE/COMMIT/RESERVE
	DWORD Protect;	// PAGE_EXECUTE_READWRITE etc
	DWORD Type;	// MEM_IMAGE/MAPPED/PRIVATE
} MEMORY_BASIC_INFORMATION32, *PMEMORY_BASIC_INFORMATION32;

typedef struct _MEMORY_BASIC_INFORMATION64 {
	ULONGLONG BaseAddress;
	ULONGLONG AllocationBase;
	DWORD     AllocationProtect;
	DWORD     __alignment1;
	ULONGLONG RegionSize;
	DWORD     State;
	DWORD     Protect;
	DWORD     Type;
	DWORD     __alignment2;
} MEMORY_BASIC_INFORMATION64, *PMEMORY_BASIC_INFORMATION64;

SIZE_T
WINAPI
VirtualQueryEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	PMEMORY_BASIC_INFORMATION32 lpBuffer,
	SIZE_T dwLength	// sizeof lpBuffer
);


EOS

	new_api_c <<EOS, 'advapi32'
#line #{__LINE__}

#define SE_PRIVILEGE_ENABLED_BY_DEFAULT (0x00000001L)
#define SE_PRIVILEGE_ENABLED            (0x00000002L)
#define SE_PRIVILEGE_REMOVED            (0X00000004L)
#define SE_PRIVILEGE_USED_FOR_ACCESS    (0x80000000L)

#define TOKEN_ASSIGN_PRIMARY    (0x0001)
#define TOKEN_DUPLICATE         (0x0002)
#define TOKEN_IMPERSONATE       (0x0004)
#define TOKEN_QUERY             (0x0008)
#define TOKEN_QUERY_SOURCE      (0x0010)
#define TOKEN_ADJUST_PRIVILEGES (0x0020)
#define TOKEN_ADJUST_GROUPS     (0x0040)
#define TOKEN_ADJUST_DEFAULT    (0x0080)
#define TOKEN_ADJUST_SESSIONID  (0x0100)

typedef struct _LUID {
	DWORD LowPart;
	LONG HighPart;
} LUID, *PLUID;

typedef struct _LUID_AND_ATTRIBUTES {
	LUID Luid;
	DWORD Attributes;
} LUID_AND_ATTRIBUTES, * PLUID_AND_ATTRIBUTES;

typedef struct _TOKEN_PRIVILEGES {
	DWORD PrivilegeCount;
	LUID_AND_ATTRIBUTES Privileges[1];
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;


BOOL
WINAPI
LookupPrivilegeNameA(
	__in_opt LPCSTR lpSystemName,
	__in     PLUID   lpLuid,
	__out    LPSTR lpName,
	__inout  LPDWORD cchName);

BOOL
WINAPI
LookupPrivilegeValueA(
	__in_opt LPCSTR lpSystemName,
	__in     LPCSTR lpName,
	__out    PLUID  lpLuid);

BOOL
WINAPI
AdjustTokenPrivileges (
	__in      HANDLE TokenHandle,
	__in      BOOL DisableAllPrivileges,
	__in_opt  PTOKEN_PRIVILEGES NewState,
	__in      DWORD BufferLength,
	__out     PTOKEN_PRIVILEGES PreviousState,
	__out_opt DWORD *ReturnLength);

BOOL
WINAPI
OpenProcessToken (
	__in  HANDLE ProcessHandle,
	__in  DWORD DesiredAccess,
	__out HANDLE *TokenHandle);


BOOL
WINAPI
OpenThreadToken (
	__in  HANDLE ThreadHandle,
	__in  DWORD DesiredAccess,
	__in  BOOL OpenAsSelf,
	__out HANDLE *TokenHandle);
EOS
	SE_DEBUG_NAME = 'SeDebugPrivilege'
	
	new_api_c <<EOS, 'psapi'
#line #{__LINE__}

BOOL
WINAPI
EnumProcesses(
	DWORD * lpidProcess,
	DWORD   cb,
	DWORD * cbNeeded);

BOOL
WINAPI
EnumProcessModules(
	HANDLE hProcess,
	HMODULE *lphModule,
	DWORD cb,
	LPDWORD lpcbNeeded);

DWORD
WINAPI
GetModuleFileNameExA(
	HANDLE hProcess,
	HMODULE hModule,
	LPSTR lpFilename,
	DWORD nSize);
EOS
 
	# convert a native function return value
	# if the native does not have the zero_not_fail attribute, convert 0
	#  to nil, and print a message on stdout
        def self.convert_ret_c2rb(fproto, ret)
		if ret == 0 and not fproto.has_attribute 'zero_not_fail'
			puts "WinAPI: error in #{fproto.name}: #{last_error_msg}" if $VERBOSE
			nil
		else super(fproto, ret)
		end
	end

	# retrieve the textual error message relative to GetLastError
	def self.last_error_msg(errno = getlasterror)
		message = ' '*512
		if formatmessagea(FORMAT_MESSAGE_FROM_SYSTEM, nil, errno, 0, message, message.length, nil) == 0
			message = 'unknown error %x' % errno
		else
			message = message[0, message.index(?\0)] if message.index(?\0)
			message.chomp!
		end
		message
	end
end

class WinOS < OS
	class Process < OS::Process
		# on-demand cached openprocess(ALL_ACCESS) handle
		def handle
			@handle ||= WinAPI.openprocess(WinAPI::PROCESS_ALL_ACCESS, 0, @pid)
		end
		def handle=(h) @handle = h end

		# return/create a WindowsRemoteString
		def memory
			@memory ||= WindowsRemoteString.new(handle)
		end
		def memory=(m) @memory = m end

		def debugger
			@debugger ||= WinDebugger.new(@pid)
		end
		def debugger=(d) @debugger = d end

		# returns the memory address size of the target process
		# hardcoded to 32 for now
		def addrsz; 32 ; end

		# retrieve the process Module list from EnumProcessModules & GetModuleFileNameExA
		# returns nil if we couldn't openprocess
		def modules
			oldverb, $VERBOSE = $VERBOSE, false	# avoid warning pollution from getmodfnamea

			self.handle
			# if we couldn't open a handle with ALL_ACCESS, retry with minimal rights
			@handle ||= WinAPI.openprocess(WinAPI::PROCESS_QUERY_INFORMATION | WinAPI::PROCESS_VM_READ, 0, @pid)
			return if not @handle
			mods = ' '*4096
			len = [0].pack('L')
			ret = []
			if WinAPI.enumprocessmodules(@handle, mods, mods.length, len)
				len = len.unpack('L').first
				mods[0, len].unpack('L*').each { |mod|
					path = ' ' * 512
					m = Process::Module.new
					m.addr = mod
					if len = WinAPI.getmodulefilenameexa(handle, mod, path, path.length)
						m.path = path[0, len]
					end
					ret << m
				}
			end
			ret
		ensure
			$VERBOSE = oldverb
		end

		# return the list of threads in the current process
		def threads
			h = WinAPI.createtoolhelp32snapshot(WinAPI::TH32CS_SNAPTHREAD, 0)
			list = []
			te = WinAPI.alloc_c_struct('THREADENTRY32', :dwsize => :size)
			return if not WinAPI.thread32first(h, te)
			loop do
				list << te['th32threadid'] if te['th32ownerprocessid'] == pid
				break if not WinAPI.thread32next(h, te)
			end
			WinAPI.closehandle(h)
			list
		end

		# return a list of [addr_start, length, perms]
		def mappings
			addr = 0
			list = []
			info = WinAPI.alloc_c_struct("MEMORY_BASIC_INFORMATION#{addrsz}")

			while WinAPI.virtualqueryex(handle, addr, info, info.length)
				addr += info[:regionsize]
				next unless info[:state] & WinAPI::MEM_COMMIT > 0

				prot = {
					WinAPI::PAGE_NOACCESS => '---',
					WinAPI::PAGE_READONLY => 'r--',
					WinAPI::PAGE_READWRITE => 'rw-',
					WinAPI::PAGE_WRITECOPY => 'rw-',
					WinAPI::PAGE_EXECUTE => '--x',
					WinAPI::PAGE_EXECUTE_READ => 'r-x',
					WinAPI::PAGE_EXECUTE_READWRITE => 'rwx',
					WinAPI::PAGE_EXECUTE_WRITECOPY => 'rwx'
				}[info[:protect] & 0xff]
				prot << 'g' if info[:protect] & WinAPI::PAGE_GUARD > 0
				prot << 'p' if info[:type]    & WinAPI::MEM_PRIVATE > 0

				list << [info[:baseaddress], info[:regionsize], prot]
			end

			list
		end
	end

class << self
	# try to enable debug privilege in current process
	def get_debug_privilege
		htok = [0].pack('L')
		return if not WinAPI.openprocesstoken(WinAPI.getcurrentprocess(), WinAPI::TOKEN_ADJUST_PRIVILEGES | WinAPI::TOKEN_QUERY, htok)
		luid = [0, 0].pack('LL')
		return if not WinAPI.lookupprivilegevaluea(nil, WinAPI::SE_DEBUG_NAME, luid)

		# priv.PrivilegeCount = 1;
		# priv.Privileges[0].Luid = luid;
		# priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		priv = luid.unpack('LL').unshift(1).push(WinAPI::SE_PRIVILEGE_ENABLED).pack('LLLL')
		return if not WinAPI.adjusttokenprivileges(htok.unpack('L').first, 0, priv, 0, nil, nil)

		true
	end

	# returns an array of Processes, with pid/module listing
	def list_processes
		tab = ' '*4096
		int = [0].pack('L')
		return if not WinAPI.enumprocesses(tab, tab.length, int)
		pids = tab[0, int.unpack('L').first].unpack('L*')
		pids.map { |pid| Process.new(pid) }
	end

	# create a debugger for the target pid/path
	def create_debugger(path)
		WinDebugger.new(path)
	end

	# Injects a shellcode into the memory space of targetproc
	# target is a WinOS::Process
	# shellcode may be a String (raw shellcode) or an EncodedData
	# With an EncodedData, unresolved relocations are solved using
	# exports of modules from the target address space ; also the
	# shellcode need not be position-independant.
	def inject_shellcode(target, shellcode)
		raise 'cannot open target memory' if not remote_mem = target.memory
		return if not injectaddr = WinAPI.virtualallocex(target.handle, 0, shellcode.length,
				WinAPI::MEM_COMMIT | WinAPI::MEM_RESERVE, WinAPI::PAGE_EXECUTE_READWRITE)
		puts 'remote buffer at %x' % injectaddr if $VERBOSE

		if shellcode.kind_of? EncodedData
			fixup_shellcode_relocs(shellcode, target, remote_mem)
			shellcode.fixup! shellcode.binding(injectaddr)
			r = shellcode.reloc.values.map { |r_| r_.target }
			raise "unresolved shellcode relocs #{r.join(', ')}" if not r.empty?
			shellcode = shellcode.data
		end

		# inject the shellcode
		remote_mem[injectaddr, shellcode.length] = shellcode

		injectaddr
	end

	def fixup_shellcode_relocs(shellcode, target, remote_mem)
		ext = shellcode.reloc_externals
		binding = {}
		while e = ext.pop
			next if binding[e]
			next if not lib = WindowsExports::EXPORT[e]	# XXX could scan all exports... LoadLibrary ftw
			next if not m = target.modules.find { |m_| m_.path.downcase.include? lib.downcase }
			lib = LoadedPE.load(remote_mem[m.addr, 0x1000_0000])
			lib.decode_header
			lib.decode_exports
			lib.export.exports.each { |e_|
				next if not e_.name or not e_.target
				binding[e_.name] = m.addr + lib.label_rva(e_.target)
			}
			shellcode.fixup! binding
		end
	end

	# creates a new thread in the target process, with the specified start address
	def createthread(target, startaddr)
		WinAPI.createremotethread(target.handle, 0, 0, startaddr, 0, 0, 0)
	end

	# calls inject_shellcode and createthread
	def inject_run_shellcode(target, shellcode)
		raise "failed to inject shellcode" if not addr = inject_shellcode(target, shellcode)
		createthread(target, addr)
	end

	# returns a Process associated to the process handle
	def open_process_handle(h)
		pr = Process.new(WinAPI.getprocessid(h))
		pr.handle = h
		pr
	end

	# returns the Process associated to pid if it is alive
	def open_process(pid)
		if h = WinAPI.openprocess(WinAPI::PROCESS_QUERY_INFORMATION, 0, pid)	# check liveness
			WinAPI.closehandle(h)
			Process.new(pid)
		end
	end
end	# class << self
end

class WindowsRemoteString < VirtualString
	def self.open_pid(pid, access = nil)
		if access
			handle = WinAPI.openprocess(access, 0, pid)
		else
			handle = WinAPI.openprocess(WinAPI::PROCESS_ALL_ACCESS, 0, pid)
			if not handle
				puts "cannot openprocess ALL_ACCESS pid #{pid}, try ro" if $VERBOSE
				handle = WinAPI.openprocess(WinAPI::PROCESS_VM_READ, 0, pid)
			end
		end
		raise "OpenProcess(#{pid}): #{WinAPI.last_error_msg}" if not handle

		new(handle)
	end

	attr_accessor :handle

	# returns a virtual string proxying the specified process memory range
	# reads are cached (4096 aligned bytes read at once)
	# writes are done directly (if handle has appropriate privileges)
	def initialize(handle, addr_start=0, length=nil)
		@handle = handle
		length ||= 1 << (WinOS.open_process_handle(@handle).addrsz rescue 32)
		super(addr_start, length)
	end

	def dup(addr = @addr_start, len = @length)
		self.class.new(@handle, addr, len)
	end

	def rewrite_at(addr, data)
		WinAPI.writeprocessmemory(@handle, addr, data, data.length, nil)
	end

	def get_page(addr, len=@pagelength)
		page = [0].pack('C')*len
		return if WinAPI.readprocessmemory(@handle, addr, page, len, 0) == 0
		page
	end
end

class WinDbgAPI
	# pid => VirtualString
	attr_accessor :mem
	# pid => handle
	attr_accessor :hprocess
	# pid => (tid => handle)
	attr_accessor :hthread

	# creates a new debugger for target (a PID or an exe filename)
	def initialize(target, debug_children = false)
		@mem = {}
		@hprocess = {}
		@hthread = {}
		begin
			pid = Integer(target)
			WinAPI.debugactiveprocess(pid)
			WinAPI.debugsetprocesskillonexit(0) rescue nil
			@mem[pid] = WindowsRemoteString.open_pid(pid)
		rescue ArgumentError
			# *(int*)&startupinfo = sizeof(startupinfo);
			startupinfo = [17*[0].pack('L').length, *([0]*16)].pack('L*')
			processinfo = [0, 0, 0, 0].pack('L*')
			flags = WinAPI::DEBUG_PROCESS
			flags |= WinAPI::DEBUG_ONLY_THIS_PROCESS if not debug_children
			target = target.dup if target.frozen?
			h = WinAPI.createprocessa(nil, target, nil, nil, 0, flags, nil, nil, startupinfo, processinfo)
			raise "CreateProcess: #{WinAPI.last_error_msg}" if not h
			hprocess, hthread, pid, tid = processinfo.unpack('LLLL')
			WinAPI.closehandle(hthread)
			@mem[pid] = WindowsRemoteString.new(hprocess) # need @mem not empty (terminate condition of debugloop)
		end
	end

	# thread context (register values)
	class Context
		OFFSETS = {}
		OFFSETS[:ctxflags] = 0
		%w[dr0 dr1 dr2 dr3 dr6 dr7].each { |reg| OFFSETS[reg.to_sym] = OFFSETS.values.max + 4 }
		OFFSETS[:fpctrl] = OFFSETS.values.max + 4
		OFFSETS[:fpstatus] = OFFSETS.values.max + 4
		OFFSETS[:fptag] = OFFSETS.values.max + 4
		OFFSETS[:fperroffset] = OFFSETS.values.max + 4
		OFFSETS[:fperrselect] = OFFSETS.values.max + 4
		OFFSETS[:fpdataoffset] = OFFSETS.values.max + 4
		OFFSETS[:fpdataselect] = OFFSETS.values.max + 4
		OFFSETS[:fpregs] = OFFSETS.values.max + 4
		OFFSETS[:fpcr0] = OFFSETS.values.max + 80
		%w[gs fs es ds edi esi ebx edx ecx eax ebp eip cs eflags esp ss].each { |reg|
			OFFSETS[reg.to_sym] = OFFSETS.values.max + 4
		}

		attr_accessor :hthread, :ctx
		# retrieves the thread context
		def initialize(hthread, flags)
			@hthread = hthread
			@ctx = [0].pack('C') * (OFFSETS.values.max + 4 + 512)
			@flags = flags
			update
		end

		def update(flags=@flags)
			set_val(:ctxflags, flags)
			WinAPI.getthreadcontext(@hthread, @ctx)
		end

		# returns the value of an unsigned int register
		def [](reg)
			raise "invalid register #{reg.inspect}" if not o = OFFSETS[reg]
			@ctx[o, 4].unpack('L').first
		end

		# updates the value of an unsigned int register
		def []=(reg, value)
			set_val(reg, value)
			commit
		end

		# updates the local copy of the context, do not commit
		def set_val(reg, value)
			raise "invalid register #{reg.inspect}" if not o = OFFSETS[reg]
			@ctx[o, 4] = [value].pack('L')
		end

		# updates the thread registers from the local copy
		def commit
			WinAPI.setthreadcontext(@hthread, @ctx)
		end

		def to_hash
			h = {}
			OFFSETS.each_key { |k| h[k] = self[k] }
			h
		end
	end

	# returns the specified thread context
	def get_context(pid, tid, flags = WinAPI::CONTEXT86_FULL | WinAPI::CONTEXT86_DEBUG_REGISTERS)
		Context.new(@hthread[pid][tid], flags)
	end

	# classes for debug informations
	class ExceptionInfo
		attr_accessor :code, :flags, :recordptr, :addr, :nparam, :info, :firstchance
		def initialize(str)
			@code, @flags, @recordptr, @addr, @nparam, @info, @firstchance = str.unpack('LLLLLC60L')
		end
	end
	class CreateThreadInfo
		attr_accessor :hthread, :threadlocalbase, :startaddr
		def initialize(str)
			@hthread, @threadlocalbase, @startaddr = str.unpack('LLL')
		end
	end
	class CreateProcessInfo
		attr_accessor :hfile, :hprocess, :hthread, :imagebase, :debugfileoff, :debugfilesize, :threadlocalbase, :startaddr, :imagename, :unicode
		def initialize(str)
			@hfile, @hprocess, @hthread, @imagebase, @debugfileoff, @debugfilesize, @threadlocalbase,
				@startaddr, @imagename, @unicode = str.unpack('LLLLLLLLLS')
		end
	end
	class ExitThreadInfo
		attr_accessor :exitcode
		def initialize(str)
			@exitcode = *str.unpack('L')
		end
	end
	class ExitProcessInfo
		attr_accessor :exitcode
		def initialize(str)
			@exitcode = *str.unpack('L')
		end
	end
	class LoadDllInfo
		attr_accessor :hfile, :imagebase, :debugfileoff, :debugfilesize, :imagename, :unicode
		def initialize(str)
			@hfile, @imagebase, @debugfileoff, @debugfilesize, @imagename, @unicode = str.unpack('LLLLLS')
		end
	end
	class UnloadDllInfo
		attr_accessor :imagebase
		def initialize(str)
			@imagebase = *str.unpack('L')
		end
	end
	class OutputDebugStringInfo
		attr_accessor :ptr, :unicode, :length
		def initialize(str)
			@ptr, @unicode, @length = str.unpack('LSS')
		end
	end
	class RipInfo
		attr_accessor :error, :type
		def initialize(str)
			@error, @type = str.unpack('LL')
		end
	end

	# returns a string suitable for use as a debugevent structure
	def debugevent_alloc
		# on wxpsp2, debugevent is at most 24*uint
		[0].pack('L')*30
	end

	# waits for debug events
	# dispatches to the different handler_*
	# custom handlers should call the default version (especially for newprocess/newthread/endprocess/endthread)
	# if given a block, yields { |pid, tid, code, rawinfo| }
	# if the block returns something not numeric, dispatch_debugevent is called
	def loop
		raw = debugevent_alloc
		while not @mem.empty?
			return if not ev = waitfordebugevent(raw)
			ret = nil
			ret = yield(*ev) if block_given?
			ret = dispatch_debugevent(*ev) if not ret.kind_of? ::Integer
			ret = WinAPI::DBG_CONTINUE if not ret.kind_of? ::Integer
			continuedebugevent(ev[0], ev[1], ret)
		end
	end

	# waits for a debug event (will put the current [debugger] process to sleep)
	# returns [pid, tid, eventcode, eventdata] or nil
	def waitfordebugevent(raw = debugevent_alloc, timeout = WinAPI::INFINITE)
		if WinAPI.waitfordebugevent(raw, timeout)
			code, pid, tid, info = raw.unpack('LLLa*')
			info = decode_info(code, info)
			predispatch_debugevent(pid, tid, code, info)
			[pid, tid, code, info]
		end
	end

	# tells the target pid:tid to resume
	def continuedebugevent(pid, tid, cont=WinAPI::DBG_CONTINUE)
		WinAPI.continuedebugevent(pid, tid, cont)
	end

	# casts a raw info to the corresponding object according to code
	def decode_info(code, info)
		c = {
			WinAPI::EXCEPTION_DEBUG_EVENT => ExceptionInfo,
			WinAPI::CREATE_PROCESS_DEBUG_EVENT => CreateProcessInfo,
			WinAPI::CREATE_THREAD_DEBUG_EVENT => CreateThreadInfo,
			WinAPI::EXIT_PROCESS_DEBUG_EVENT => ExitProcessInfo,
			WinAPI::EXIT_THREAD_DEBUG_EVENT => ExitThreadInfo,
			WinAPI::LOAD_DLL_DEBUG_EVENT => LoadDllInfo,
			WinAPI::UNLOAD_DLL_DEBUG_EVENT => UnloadDllInfo,
			WinAPI::OUTPUT_DEBUG_STRING_EVENT => OutputDebugStringInfo,
			WinAPI::RIP_EVENT => RipInfo,
		}[code]
		c ? c.new(info) : info
	end

	# update this object internal state from debug events (new thread/process)
	def predispatch_debugevent(pid, tid, code, info)
		case code
		when WinAPI::CREATE_PROCESS_DEBUG_EVENT; prehandler_newprocess pid, tid, info
		when WinAPI::CREATE_THREAD_DEBUG_EVENT;  prehandler_newthread  pid, tid, info
		# can't prehandle_endprocess/thread, the handler runs after us and may need the handles
		end
	end

	# handles one debug event
	# calls the corresponding handler
	# returns the handler return value
	def dispatch_debugevent(pid, tid, code, info)
		case code
		when WinAPI::EXCEPTION_DEBUG_EVENT;      handler_exception   pid, tid, info
		when WinAPI::CREATE_PROCESS_DEBUG_EVENT; handler_newprocess  pid, tid, info
		when WinAPI::CREATE_THREAD_DEBUG_EVENT;  handler_newthread   pid, tid, info
		when WinAPI::EXIT_PROCESS_DEBUG_EVENT;   handler_endprocess  pid, tid, info
		when WinAPI::EXIT_THREAD_DEBUG_EVENT;    handler_endthread   pid, tid, info
		when WinAPI::LOAD_DLL_DEBUG_EVENT;       handler_loaddll     pid, tid, info
		when WinAPI::UNLOAD_DLL_DEBUG_EVENT;     handler_unloaddll   pid, tid, info
		when WinAPI::OUTPUT_DEBUG_STRING_EVENT;  handler_debugstring pid, tid, info
		when WinAPI::RIP_EVENT;                  handler_rip         pid, tid, info
		else                                     handler_unknown     pid, tid, code, info
		end
	end

	def handler_exception(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} exception" if $DEBUG
		case info.code
		when WinAPI::STATUS_ACCESS_VIOLATION
			# fix fs bug in xpsp1
			ctx = get_context(pid, tid)
			if ctx[:fs] != 0x3b
				puts "wdbg: #{pid}:#{tid} fix fs bug" if $DEBUG
				ctx[:fs] = 0x3b
				return WinAPI::DBG_CONTINUE
			end
			WinAPI::DBG_EXCEPTION_NOT_HANDLED
		when WinAPI::STATUS_BREAKPOINT
			# we must ack ntdll interrupts on process start
			# but we should not mask process-generated exceptions by default..
			WinAPI::DBG_CONTINUE
		when WinAPI::STATUS_SINGLE_STEP
			WinAPI::DBG_CONTINUE
		else
			WinAPI::DBG_EXCEPTION_NOT_HANDLED
		end
	end

	def prehandler_newprocess(pid, tid, info)
		@mem[pid] ||= WindowsRemoteString.new(info.hprocess)
		@hprocess[pid] = info.hprocess
		prehandler_newthread(pid, tid, info)
	end

	def prehandler_newthread(pid, tid, info)
		@hthread[pid] ||= {}
		@hthread[pid][tid] = info.hthread
	end

	def prehandler_endthread(pid, tid, info)
		@hthread[pid].delete tid
	end

	def prehandler_endprocess(pid, tid, info)
		@hprocess.delete pid
		@hthread.delete pid
		@mem.delete pid
	end

	def handler_newprocess(pid, tid, info)
		str = read_str_indirect(pid, info.imagename, info.unicode)
		puts "wdbg: #{pid}:#{tid} new process #{str.inspect} at #{'0x%08X' % info.imagebase}" if $DEBUG
		handler_newthread(pid, tid, info)
		WinAPI::DBG_CONTINUE
	end

	def handler_newthread(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} new thread at #{'0x%08X' % info.startaddr}" if $DEBUG
		WinAPI::DBG_CONTINUE
	end

	def handler_endprocess(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} process died" if $DEBUG
		prehandler_endprocess(pid, tid, info)
		WinAPI::DBG_CONTINUE
	end

	def handler_endthread(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} thread died" if $DEBUG
		prehandler_endthread(pid, tid, info)
		WinAPI::DBG_CONTINUE
	end

	def handler_loaddll(pid, tid, info)
		if $DEBUG
			dll = LoadedPE.load(@mem[pid][info.imagebase, 0x1000_0000])
			dll.decode_header
			dll.decode_exports
			str = (dll.export ? dll.export.libname : read_str_indirect(pid, info.imagename, info.unicode))
			puts "wdbg: #{pid}:#{tid} loaddll #{str.inspect} at #{'0x%08X' % info.imagebase}"
		end
		WinAPI.closehandle(info.hfile)
		WinAPI::DBG_CONTINUE
	end

	def handler_unloaddll(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} unloaddll #{'0x%08X' % info.imagebase}" if $DEBUG
		WinAPI::DBG_CONTINUE
	end

	def handler_debugstring(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} debugstring #{read_str_indirect(pid, info.ptr, info.unicode)}" if $VERBOSE
		WinAPI::DBG_CONTINUE
	end

	def handler_rip(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} rip" if $VERBOSE
		WinAPI::DBG_CONTINUE
	end

	def handler_unknown(pid, tid, code, raw)
		puts "wdbg: #{pid}:#{tid} unknown debugevent #{'0x%X' % code} #{raw.inspect}" if $VERBOSE
		WinAPI::DBG_CONTINUE
	end

	# reads a null-terminated string from a pointer in the remote address space
	def read_str_indirect(pid, ptr, unicode=0)
		return '' if not ptr or ptr == 0
		ptr = @mem[pid][ptr, 4].unpack('L').first
		str = @mem[pid][ptr, 512]
		str = str.unpack('S*').pack('C*') if unicode != 0
		str = str[0, str.index(?\0)] if str.index(?\0)
		str
	end

	def break(pid)
		WinAPI.debugbreakprocess(@hprocess[pid])
	end


	attr_accessor :logger
	def puts(*s)
		@logger ||= $stdout
		@logger.puts(*s)
	end
end

# this class implements a high-level API over the Windows debugging primitives
class WinDebugger < Debugger
	attr_accessor :dbg
	def initialize(pid)
		@dbg = WinDbgAPI.new(pid)
		@dbg.logger = self
		@pid = @dbg.mem.keys.first
		@cpu = Ia32.new(WinOS.open_process(@pid).addrsz)
		@memory = @dbg.mem[@pid]
		super()
		# get a valid @tid (for reg values etc)
		@dbg.loop { |pid_, tid, code, info|
			update_dbgev([pid_, tid, code, info])
			case code
			when WinAPI::CREATE_THREAD_DEBUG_EVENT, WinAPI::CREATE_PROCESS_DEBUG_EVENT
				@tid = tid
				break
			end
		}
		@continuecode = WinAPI::DBG_CONTINUE	#WinAPI::DBG_EXCEPTION_NOT_HANDLED
	end

	def os_process
		WinOS.open_process(@pid)
	end

	def tid=(tid)
		super(tid)
		@ctx = nil
	end

	def ctx
		@ctx ||= @dbg.get_context(@pid, @tid)
	end

	def invalidate
		@ctx = nil
		super()
	end

	def get_reg_value(r)
		ctx[r]
	end

	def set_reg_value(r, v)
		ctx[r] = v
	end

	def enable_bp(addr)
		return if not b = @breakpoint[addr]
		@cpu.dbg_enable_bp(self, addr, b)
		b.state = :active
	end

	def disable_bp(addr)
		return if not b = @breakpoint[addr]
		@cpu.dbg_disable_bp(self, addr, b)
		b.state = :inactive
	end

	def do_continue(*a)
		@cpu.dbg_disable_singlestep(self)
		@dbg.continuedebugevent(@pid, @tid, @continuecode)
		@state = :running
		@info = 'continue'
	end

	def do_singlestep(*a)
		@cpu.dbg_enable_singlestep(self)
		@dbg.continuedebugevent(@pid, @tid, @continuecode)
		@state = :running
		@info = 'singlestep'
	end

	def do_check_target
		ev = @dbg.waitfordebugevent(@dbg.debugevent_alloc, 0)
		update_dbgev(ev)
	end


	def do_wait_target
		@dbg.loop { |*ev|
			update_dbgev(ev)
			break if @state != :running
		} if @state == :running
	end

	def break
		@dbg.break(@pid) if @state == :running
	end

	def kill(*a)
		WinAPI.terminateprocess(@dbg.hprocess[@pid], 0)
		#@state = :dead		# dont mark it dead while the process exists
		#@info = 'killed'
	end

	def pass_current_exception(doit = true)
		@continuecode = (doit ? WinAPI::DBG_EXCEPTION_NOT_HANDLED : WinAPI::DBG_CONTINUE)
	end

	def update_dbgev(ev)
		return if not ev
		pid, tid, code, info = ev
		return if pid != @pid
		invalidate
		@continuecode = WinAPI::DBG_CONTINUE
		case code
		when WinAPI::EXCEPTION_DEBUG_EVENT
			# attr :code, :flags, :recordptr, :addr, :nparam, :info, :firstchance
			case info.code
			when WinAPI::STATUS_ACCESS_VIOLATION
				# fix fs bug in xpsp1
				if @cpu.shortname == 'ia32' and ctx = @dbg.get_context(pid, tid) and ctx[:fs] != 0x3b
					puts "wdbg: #{pid}:#{tid} fix fs bug" if $DEBUG
					ctx[:fs] = 0x3b
					@dbg.continuedebugevent(pid, tid, WinAPI::DBG_CONTINUE)
					return
				end
				@state = :stopped
				@info = "access violation at #{Expression[info.addr]} (#{info.firstchance == 0 ? '1st' : '2nd'} chance)"
			when WinAPI::STATUS_BREAKPOINT, WinAPI::STATUS_SINGLE_STEP
				@state = :stopped
				@info = nil
			else
				@state = :stopped
				@info = "unknown #{info.inspect}"
				@continuecode = WinAPI::DBG_EXCEPTION_NOT_HANDLED
			end
		when WinAPI::CREATE_THREAD_DEBUG_EVENT
			@state = :stopped
			@info = "thread #{tid} created"
		when WinAPI::EXIT_THREAD_DEBUG_EVENT
			@state = :stopped
			@info = "thread #{tid} died, exitcode #{info.exitcode}"
		when WinAPI::EXIT_PROCESS_DEBUG_EVENT
			@state = :dead
			@info = "process died, exitcode #{info.exitcode}"
		else
			# loadsyms(info.imagebase) if code == WinAPI::LOAD_DLL_DEBUG_EVENT
			@dbg.continuedebugevent(pid, tid, WinAPI::DBG_CONTINUE)
			return
		end
		@tid = tid
	end

	def ui_command_setup(ui)
		ui.new_command('pass_current_exception', 'pass the current exception to the debuggee') { |arg|
			if arg.strip == 'no'; pass_current_exception(false) ; puts "ignore exception"
			else pass_current_exception ; puts "forward exception"
			end
		}
		ui.keyboard_callback_ctrl[:f5] = lambda { pass_current_exception ; ui.wrap_run { continue } }
	end
end
end
