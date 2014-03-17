#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/os/main'
require 'metasm/dynldr'

module Metasm
class WinAPI < DynLdr
  def self.api_not_found(lib, func)
    puts "could not find symbol #{func.name.inspect} in #{lib.inspect}" if $VERBOSE and not func.attributes.to_a.include?('optional')
  end

  new_api_c <<EOS, 'kernel32'
#line #{__LINE__}

typedef char CHAR;
typedef unsigned char BYTE;
typedef unsigned short WORD, USHORT;
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

#define INVALID_HANDLE_VALUE (HANDLE)-1
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

#define MAX_PATH 260

#define EXCEPTION_NONCONTINUABLE 0x1    // Noncontinuable exception
#define EXCEPTION_MAXIMUM_PARAMETERS 15 // maximum number of exception parameters

typedef struct _EXCEPTION_RECORD {
  DWORD ExceptionCode;
  DWORD ExceptionFlags;		// noncontinuable
  struct _EXCEPTION_RECORD *ExceptionRecord;
  PVOID ExceptionAddress;
  DWORD NumberParameters;
  ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

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

typedef struct _EXCEPTION_DEBUG_INFO {
  EXCEPTION_RECORD ExceptionRecord;
  DWORD dwFirstChance;
} EXCEPTION_DEBUG_INFO, *LPEXCEPTION_DEBUG_INFO;

typedef struct _EXCEPTION_DEBUG_INFO32 {
  EXCEPTION_RECORD32 ExceptionRecord;
  DWORD dwFirstChance;
} EXCEPTION_DEBUG_INFO32;

typedef struct _EXCEPTION_DEBUG_INFO64 {
  EXCEPTION_RECORD64 ExceptionRecord;
  DWORD dwFirstChance;
} EXCEPTION_DEBUG_INFO64;

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
  // DWORD pad64; (implicit)
  union {
    EXCEPTION_DEBUG_INFO Exception;
    EXCEPTION_DEBUG_INFO32 Exception32;
    CREATE_THREAD_DEBUG_INFO CreateThread;
    CREATE_PROCESS_DEBUG_INFO CreateProcess;
    EXIT_THREAD_DEBUG_INFO ExitThread;
    EXIT_PROCESS_DEBUG_INFO ExitProcess;
    LOAD_DLL_DEBUG_INFO LoadDll;
    UNLOAD_DLL_DEBUG_INFO UnloadDll;
    OUTPUT_DEBUG_STRING_INFO DebugString;
    RIP_INFO RipInfo;
  } u;
} DEBUG_EVENT, *LPDEBUG_EVENT;

// XXX conflict with structure name..
#define CONTEXT_I386    0x00010000
#define CONTEXT_AMD64   0x00100000

#define CONTEXT_CONTROL             0x00000001L // SS:SP, CS:IP, FLAGS, BP
#define CONTEXT_INTEGER             0x00000002L // AX, BX, CX, DX, SI, DI
#define CONTEXT_SEGMENTS            0x00000004L // DS, ES, FS, GS
#define CONTEXT_FLOATING_POINT      0x00000008L // 387 state
#define CONTEXT_DEBUG_REGISTERS     0x00000010L // DB 0-3,6,7
#define CONTEXT_EXTENDED_REGISTERS  0x00000020L // cpu specific extensions
#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)
#define CONTEXT_ALL (CONTEXT_FULL | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS)

#define CONTEXT_I386_FULL CONTEXT_I386 | CONTEXT_FULL
#define CONTEXT_I386_ALL  CONTEXT_I386 | CONTEXT_ALL
#define CONTEXT_AMD64_FULL CONTEXT_AMD64 | CONTEXT_FULL
#define CONTEXT_AMD64_ALL  CONTEXT_AMD64 | CONTEXT_ALL

#define MAXIMUM_SUPPORTED_EXTENSION     512
#define SIZE_OF_80387_REGISTERS      80

typedef struct _FPREG { BYTE b[10]; } FPREG;
typedef struct _XMMREG { ULONGLONG lo, hi; } XMMREG;

typedef struct _FLOATING_SAVE_AREA {
  WORD    ControlWord;
  WORD    res0;
  WORD    StatusWord;
  WORD    res1;
  WORD    TagWord;
  WORD    res2;
  DWORD   ErrorOffset;
  WORD    ErrorSelector;
  WORD    ErrorOpcode;
  DWORD   DataOffset;
  WORD    DataSelector;
  WORD    res3;
  FPREG   St[8];
  DWORD   Cr0NpxState;
} FLOATING_SAVE_AREA, *PFLOATING_SAVE_AREA;

typedef struct _CONTEXT_I386 {
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

  XMMREG  Xmm[8];

  BYTE   ExtendedRegisters[24*16];
} *LPCONTEXT_I386, *LPCONTEXT;

typedef struct _CONTEXT_AMD64 {
  DWORD64 P1Home;	 // Register parameter home addresses.
  DWORD64 P2Home;
  DWORD64 P3Home;
  DWORD64 P4Home;
  DWORD64 P5Home;
  DWORD64 P6Home;

  DWORD ContextFlags;
  DWORD MxCsr;

  WORD   SegCs;
  WORD   SegDs;
  WORD   SegEs;
  WORD   SegFs;
  WORD   SegGs;
  WORD   SegSs;
  DWORD RFlags;

  DWORD64 Dr0;
  DWORD64 Dr1;
  DWORD64 Dr2;
  DWORD64 Dr3;
  DWORD64 Dr6;
  DWORD64 Dr7;

  DWORD64 Rax;
  DWORD64 Rcx;
  DWORD64 Rdx;
  DWORD64 Rbx;
  DWORD64 Rsp;
  DWORD64 Rbp;
  DWORD64 Rsi;
  DWORD64 Rdi;
  DWORD64 R8;
  DWORD64 R9;
  DWORD64 R10;
  DWORD64 R11;
  DWORD64 R12;
  DWORD64 R13;
  DWORD64 R14;
  DWORD64 R15;
  DWORD64 Rip;

  WORD ControlWord;
  WORD StatusWord;
  BYTE TagWord;
  BYTE resv1;
  WORD ErrorOpcode;
  DWORD ErrorOffset;
  WORD ErrorSelector;
  WORD resv2;
  DWORD DataAtOffset;
  WORD DataSelector;
  WORD resv3;
  DWORD MxCsr_f;
  DWORD MxCsrMask;
  XMMREG ST[8];
  XMMREG Xmm[16];

  XMMREG Vector[26];
  DWORD64 VectorControl;
  
  DWORD64 DebugControl;
  DWORD64 LastBranchToRip;
  DWORD64 LastBranchFromRip;
  DWORD64 LastExceptionToRip;
  DWORD64 LastExceptionFromRip;
} *LPCONTEXT_AMD64;

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
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
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
#define THREAD_SET_LIMITED_INFORMATION (0x0400)
#define THREAD_QUERY_LIMITED_INFORMATION (0x0800)
#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3FF)


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

/* Vista onwards only..
WINBASEAPI
DWORD
WINAPI
GetThreadId(
  __in HANDLE Thread);
*/

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

WINBASEAPI
BOOL
WINAPI
__attribute__((optional))
Wow64GetThreadContext(
  __in    HANDLE hThread,
  __inout LPCONTEXT_I386 lpContext);

WINBASEAPI
BOOL
WINAPI
__attribute__((optional))
Wow64SetThreadContext(
  __in    HANDLE hThread,
  __inout LPCONTEXT_I386 lpContext);

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
__attribute__((optional))
Wow64SuspendThread(
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
#define TH32CS_INHERIT      0x80000000

HANDLE
WINAPI
CreateToolhelp32Snapshot(
  DWORD dwFlags,
  DWORD th32ProcessID
);

typedef struct tagPROCESSENTRY32
{
  DWORD   dwSize;
  DWORD   cntUsage;
  DWORD   th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD   th32ModuleID;
  DWORD   cntThreads;
  DWORD   th32ParentProcessID;
  LONG    pcPriClassBase;
  DWORD   dwFlags;
  CHAR    szExeFile[MAX_PATH];
} PROCESSENTRY32;

BOOL
WINAPI
Process32First(
  HANDLE hSnapshot,
  PROCESSENTRY32 *lppe
);
BOOL
WINAPI
ZEROOK
Process32Next(
    HANDLE hSnapshot,
    PROCESSENTRY32 *lppe
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
ZEROOK
Thread32Next(
  HANDLE hSnapshot,
  LPTHREADENTRY32 lpte
);


typedef struct tagHEAPLIST32
{
  SIZE_T dwSize;
  DWORD  th32ProcessID;   // owning process
  ULONG_PTR  th32HeapID;      // heap (in owning process context!)
  DWORD  dwFlags;
} HEAPLIST32, LPHEAPLIST32;

#define HF32_DEFAULT      1  // process default heap
#define HF32_SHARED       2  // is shared heap

BOOL
WINAPI
Heap32ListFirst(
     HANDLE hSnapshot,
     LPHEAPLIST32 lphl
);
BOOL
WINAPI
ZEROOK
Heap32ListNext(
     HANDLE hSnapshot,
     LPHEAPLIST32 lphl
);


typedef struct tagMODULEENTRY32
{
  DWORD   dwSize;
  DWORD   th32ModuleID;
  DWORD   th32ProcessID;
  DWORD   GlblcntUsage;
  DWORD   ProccntUsage;
  ULONG_PTR modBaseAddr;
  DWORD   modBaseSize;
  HMODULE hModule;
  char    szModule[256];
  char    szExePath[MAX_PATH];
} MODULEENTRY32;

BOOL
WINAPI
Module32First(
  HANDLE hSnapshot,
  MODULEENTRY32 *lpme
);
BOOL
WINAPI
ZEROOK
Module32Next(
  HANDLE hSnapshot,
  MODULEENTRY32 *lpme
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
ZEROOK
VirtualQueryEx(
  HANDLE hProcess,
  LPVOID lpAddress,
  PMEMORY_BASIC_INFORMATION32 lpBuffer,
  SIZE_T dwLength	// sizeof lpBuffer
);

typedef struct _LDT_ENTRY {
  WORD  LimitLow;
  WORD  BaseLow;
  union {
    struct {
    BYTE BaseMid;
    BYTE Flags1;
    BYTE Flags2;
    BYTE BaseHi;
  } Bytes;
  struct {
    DWORD BaseMid  :8;
    DWORD Type  :5;
    DWORD Dpl  :2;
    DWORD Pres  :1;
    DWORD LimitHi  :4;
    DWORD Sys  :1;
    DWORD Reserved_0  :1;
    DWORD Default_Big  :1;
    DWORD Granularity  :1;
    DWORD BaseHi  :8;
  } Bits;
  } HighWord;
} LDT_ENTRY;

BOOL
WINAPI
GetThreadSelectorEntry(
  HANDLE hThread,
  DWORD dwSelector,
  LDT_ENTRY *lpSelectorEntry
);

BOOL
WINAPI
__attribute__((optional))
IsWow64Process(
  HANDLE hProcess,
  BOOL *wow64
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
  
  new_api_c <<EOS, 'ntdll'
#line #{__LINE__}

typedef LONG NTSTATUS;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination
} THREADINFOCLASS;

typedef enum _MEMORYINFOCLASS {
    MemoryBasicInformation,
    MemoryDunnoLol,
    MemoryMapFileName
} MEMORYINFOCLASS;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    USHORT *Buffer;
} UNICODE_STRING;

ZEROOK
NTSTATUS
WINAPI
NtQueryInformationProcess(
  HANDLE ProcessHandle,
  PROCESSINFOCLASS ProcessInformationClass,
  PVOID ProcessInformation,
  ULONG ProcessInformationLength,
  ULONG *ReturnLength
);

ZEROOK
NTSTATUS
WINAPI
NtQueryInformationThread (
  HANDLE ThreadHandle,
  THREADINFOCLASS ThreadInformationClass,
  PVOID ThreadInformation,
  ULONG ThreadInformationLength,
  ULONG *ReturnLength
);

ZEROOK
NTSTATUS
WINAPI
NtQueryVirtualMemory (
  HANDLE ProcessHandle,
  PVOID BaseAddress,
  MEMORYINFOCLASS MemoryInformationClass,
  PVOID MemoryInformation,
  ULONG MemoryInformationLength,
  ULONG *ReturnLength
);

EOS
 
  # convert a native function return value
  # if the native does not have the zero_not_fail attribute, convert 0
  #  to nil, and print a message on stdout
        def self.convert_ret_c2rb(fproto, ret)
    @last_err_msg = nil
    if ret == 0 and not fproto.has_attribute 'zero_not_fail'
      # save error msg so that last_error_msg returns the same thing if called again
      puts "WinAPI: error in #{fproto.name}: #{@last_err_msg = last_error_msg}" if $VERBOSE
      nil
    else super(fproto, ret)
    end
  end

  # retrieve the textual error message relative to GetLastError
  def self.last_error_msg(errno = nil)
    return @last_err_msg if @last_err_msg
    errno ||= getlasterror
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
    attr_accessor :ppid
    def initialize(pid, handle=nil)
      @pid = pid
      @handle = handle
    end

    # on-demand cached openprocess(ALL_ACCESS) handle
    def handle
      @handle ||= WinAPI.openprocess(WinAPI::PROCESS_ALL_ACCESS, 0, @pid)
    end
    attr_writer :handle

    # return/create a WindowsRemoteString
    def memory
      @memory ||= WindowsRemoteString.new(handle)
    end
    attr_writer :memory

    def debugger
      @debugger ||= WinDebugger.new(@pid)
    end
    attr_writer :debugger

    # returns the memory address size of the target process
    def addrsz
      @addrsz ||= if WinAPI.respond_to?(:iswow64process)
        byte = 0.chr*8
        if WinAPI.iswow64process(handle, byte)
          if byte != 0.chr*8
            32 # target = wow64
          elsif WinAPI.iswow64process(WinAPI.getcurrentprocess, byte) and byte != 0.chr*8
            64 # us = wow64, target is not
          else
            WinAPI.host_cpu.size
          end
        else
          WinAPI.host_cpu.size
      end
      end
    end

    def modules
      WinOS.list_modules(@pid)
    end

    def threads
      WinOS.list_threads(@pid)
      end

    def heaps
      WinOS.list_heaps(@pid)
    end

    # return a list of [addr_start, length, perms]
    def mappings
      addr = 0
      list = []
      info = WinAPI.alloc_c_struct("MEMORY_BASIC_INFORMATION#{addrsz}")
      path = [0xff].pack('C') * 512

      hcache = heaps

      while WinAPI.virtualqueryex(handle, addr, info, info.length) != 0
        addr += info.regionsize
        next unless info.state & WinAPI::MEM_COMMIT > 0

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

        if h = hcache[info.baseaddress]
          a = []
          a << 'default' if h[:default]
          a << 'shared' if h[:shared]
          a << 'heap'
          #a << h[:flags].to_s(16)
          cmt = '[' + a.join(' ') + ']'
        elsif WinAPI.ntqueryvirtualmemory(handle, info.baseaddress, WinAPI::MEMORYMAPFILENAME, path, path.length, 0) == 0
          us = WinAPI.decode_c_struct('UNICODE_STRING', path)
          s = WinAPI.decode_c_ary('USHORT', us['Length']/2, WinAPI.memory_read(us['Buffer'], us['MaximumLength']))
          cmt = s.to_strz
        else
          cmt = ''
        end

        list << [info.baseaddress, info.regionsize, prot, cmt]
      end

      list
    end

    def peb_base
      @peb_base ||=
      if WinAPI.respond_to?(:ntqueryinformationprocess)
        pinfo = WinAPI.alloc_c_struct('PROCESS_BASIC_INFORMATION')
        if WinAPI.ntqueryinformationprocess(handle, WinAPI::PROCESSBASICINFORMATION, pinfo, pinfo.length, 0) == 0
          pinfo.pebbaseaddress
        end
      else
        # pre-NT: all pebs should have the same addr
        WinAPI.new_func_asm('unsigned get_peb(void)', 'mov eax, fs:[30h] ret') { WinAPI.get_peb }
      end
    end
    attr_writer :peb_base

    def terminate(exitcode=0)
      WinAPI.terminateprocess(handle, exitcode)
    end
  end

  class Thread
    attr_accessor :tid
    attr_accessor :process

    def initialize(tid, handle=nil, process=nil)
      @tid = tid
      @handle = handle
      @process = process
    end

    def handle
      @handle ||= WinAPI.openthread(WinAPI::THREAD_ALL_ACCESS, 0, @tid)
    end
    attr_writer :handle

    # return the address of the TEB for the target thread
    def teb_base
      @teb_base ||=
      if WinAPI.respond_to?(:ntqueryinformationthread)
        tinfo = WinAPI.alloc_c_struct('THREAD_BASIC_INFORMATION')
        if WinAPI.ntqueryinformationthread(handle, WinAPI::THREADBASICINFORMATION, tinfo, tinfo.length, 0) == 0
          tinfo.tebbaseaddress
        end
      else
        fs = context { |c| c[:fs] }
        ldte = WinAPI.alloc_c_struct('LDT_ENTRY')
        if WinAPI.getthreadselectorentry(handle, fs, ldte)
          ldte.baselow | (ldte.basemid << 16) | (ldte.basehi << 24)
        end
      end
    end
    attr_writer :teb_base

    # increment the suspend count of the target thread - stop at >0
    def suspend
      if WinAPI.host_cpu.size == 64 and process and process.addrsz == 32
        WinAPI.wow64suspendthread(handle)
      else
        WinAPI.suspendthread(handle)
      end
    end

    # decrease the suspend count of the target thread - runs at 0
    def resume
      WinAPI.resumethread(handle)
    end

    def terminate(exitcode=0)
      WinAPI.terminatethread(handle, exitcode)
    end

    # returns a Context object. Can be reused, refresh the values with #update (target thread must be suspended)
    # if a block is given, suspend the thread, update the context, yield it, and resume the thread
    def context
      @context ||= Context.new(self, :all)
      if block_given?
        suspend
        @context.update
        ret = yield @context
        resume
        ret
      else
        @context
      end
    end
    attr_writer :context

    class Context
      def initialize(thread, kind=:all)
        @handle = thread.handle
        tg = thread.process ? thread.process.addrsz : 32
        case WinAPI.host_cpu.shortname
        when 'ia32', 'x64'; tg = ((tg == 32) ? 'ia32' : 'x64')
        else raise "unsupported architecture #{tg}"
        end

        @getcontext = :getthreadcontext
        @setcontext = :setthreadcontext
        case tg
        when 'ia32'
          @context = WinAPI.alloc_c_struct('_CONTEXT_I386')
          @context.contextflags = WinAPI::CONTEXT_I386_ALL
          if WinAPI.host_cpu.shortname == 'x64'
            @getcontext = :wow64getthreadcontext
            @setcontext = :wow64setthreadcontext
          end
        when 'x64'
          @context = WinAPI.alloc_c_struct('_CONTEXT_AMD64')
          @context.contextflags = WinAPI::CONTEXT_AMD64_ALL
        end
      end

      # update the context to reflect the current thread reg values
      # call only when the thread is suspended
      def update
        WinAPI.send(@getcontext, @handle, @context)
      end

      def [](k)
        case k.to_s
        when /^[cdefgs]s$/i
          @context["seg#{k}"]
        when /^st(\d*)/i
          v = @context['st'][$1.to_i]
          buf = v.str[v.str_off, 10]
          # TODO check this, 'D' is 8byte wide
          buf.unpack('D')[0]
        when /^xmm(\d+)/i
          v = @context['xmm'][$1.to_i]
          (v.hi << 64) | v.lo
        when /^mmx?(\d+)/i
          @context['xmm'][$1.to_i].lo
        else
          @context[k]
        end
      end

      def []=(k, v)
        case k.to_s
        when /^[cdefgs]s$/i
          @context["seg#{k}"] = v
        when /^st(\d*)/i
          # TODO check this, 'D' is 8byte wide
          buf = [v, 0, 0].pack('DCC')
          @context['st'][$1.to_i][0, 10] = buf
        when /^xmm(\d+)/i
          kk = @context['xmm'][$1.to_i]
          kk.lo = v & ((1<<64)-1)
          kk.hi = (v>>64) & ((1<<64)-1)
        when /^mmx?(\d+)/i
          @context['xmm'][$1.to_i].lo = v
        else
          @context[k] = v
        end
        WinAPI.send(@setcontext, @handle, @context)
      end

      def method_missing(m, *a)
        if m.to_s[-1] == ?=
          super(m, *a) if a.length != 1
          send '[]=', m.to_s[0...-1], a[0]
        else
          super(m, *a) if a.length != 0
          send '[]', m
        end
      end
    end
  end

class << self
  # try to enable debug privilege in current process
  def get_debug_privilege
    # TODO use real structs / new_func_c
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

  # returns an array of Processes with pid/ppid/path filled
  def list_processes
    h = WinAPI.createtoolhelp32snapshot(WinAPI::TH32CS_SNAPPROCESS, 0)
    list = []
    pe = WinAPI.alloc_c_struct('PROCESSENTRY32', :dwsize => :size)
    return if not WinAPI.process32first(h, pe)
    loop do
      p = Process.new(pe.th32processid)
      p.ppid = pe.th32parentprocessid
      p.path = pe.szexefile.to_strz
      list << p if p.pid != 0
      break if WinAPI.process32next(h, pe) == 0
    end
    WinAPI.closehandle(h)
    list
  end

  # retrieve the list of Modules for a process with addr/size/path filled
  def list_modules(pid)
    h = WinAPI.createtoolhelp32snapshot(WinAPI::TH32CS_SNAPMODULE, pid)
    return [] if h == WinAPI::INVALID_HANDLE_VALUE
    list = []
    me = WinAPI.alloc_c_struct('MODULEENTRY32', :dwsize => :size)
    return [] if not WinAPI.module32first(h, me)
    loop do
      m = Process::Module.new
      m.addr = me.modbaseaddr
      m.size = me.modbasesize
      m.path = me.szexepath.to_strz
      list << m
      break if WinAPI.module32next(h, me) == 0
    end
    WinAPI.closehandle(h)
    list
  end

  # returns the list of thread ids of the system, optionally filtering by pid
  def list_threads(pid=nil)
    h = WinAPI.createtoolhelp32snapshot(WinAPI::TH32CS_SNAPTHREAD, 0)
    list = []
    te = WinAPI.alloc_c_struct('THREADENTRY32', :dwsize => :size)
    return [] if not WinAPI.thread32first(h, te)
    loop do
      list << te.th32threadid if not pid or te.th32ownerprocessid == pid
      break if WinAPI.thread32next(h, te) == 0
  end
    WinAPI.closehandle(h)
    list
  end

  # returns the heaps of the process, from a toolhelp snapshot SNAPHEAPLIST
  # this is a hash
  # heap_addr => { :flags => integer (heap flags)
  #                :shared => bool (from flags)
  #                :default => bool (from flags) }
  def list_heaps(pid)
    h = WinAPI.createtoolhelp32snapshot(WinAPI::TH32CS_SNAPHEAPLIST, pid)
    return [] if h == WinAPI::INVALID_HANDLE_VALUE
    ret = {}
    he = WinAPI.alloc_c_struct('HEAPLIST32', :dwsize => :size)
    return [] if not WinAPI.heap32listfirst(h, he)
    loop do
      hash = ret[he.th32heapid] = { :flags => he.dwflags }
      hash[:default] = true if hash[:flags] & WinAPI::HF32_DEFAULT == WinAPI::HF32_DEFAULT
      hash[:shared]  = true if hash[:flags] & WinAPI::HF32_SHARED  == WinAPI::HF32_SHARED
      # TODO there are lots of other flags in there ! like 0x1000 / 0x8000
      break if WinAPI.heap32listnext(h, he) == 0
    end
    WinAPI.closehandle(h)
    ret
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
    pid = WinAPI.getprocessid(h) rescue 0
    Process.new(pid, h)
  end

  # returns the Process associated to pid if it is alive
  def open_process(pid)
    Process.new(pid) if check_process(pid)
  end

  # returns true if the process pid exists and we can open it with QUERY_INFORMATION
  def check_process(pid)
    if h = WinAPI.openprocess(WinAPI::PROCESS_QUERY_INFORMATION, 0, pid)
      WinAPI.closehandle(h)
      true
    end
  end

  # returns the Thread associated to a tid if it is alive
  def open_thread(tid)
    Thread.new(tid) if check_tid(tid)
  end

  # check if the thread is alive and can be read with QUERY_INFO
  # and optionally if it belongs to pid
  def check_tid(tid, pid=nil)
    if h = WinAPI.openthread(WinAPI::THREAD_QUERY_INFORMATION, 0, tid)
      WinAPI.closehandle(h)
      not pid or list_threads(pid).include?(tid)
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

# this class implements a high-level API over the Windows debugging primitives
class WinDebugger < Debugger
  attr_accessor :os_process, :os_thread,
    :auto_fix_fs_bug,
    # is current exception handled? (arg to pass to continuedbgevt)
    :continuecode

  attr_accessor :callback_unloadlibrary, :callback_debugstring, :callback_ripevent

  def initialize(pidpath=nil)
    super()
    @pid_stuff_list << :os_process
    @tid_stuff_list << :os_thread << :ctx << :continuecode

    @auto_fix_fs_bug = false

    return if not pidpath

    begin
      npid = Integer(pidpath)
      attach(npid)
    rescue ArgumentError
      create_process(pidpath)
  end

    check_target until pid
    end

  def shortname; 'windbg'; end

  def attach(npid)
    WinAPI.debugactiveprocess(npid)
    WinAPI.debugsetprocesskillonexit(0) if WinAPI.respond_to?(:debugsetprocesskillonexit)
    100.times {
      check_target
      break if pid
    }
    raise "attach failed" if not pid
    end

  def create_process(target)
    startupinfo = WinAPI.alloc_c_struct('STARTUPINFOA', :cb => :size)
    processinfo = WinAPI.alloc_c_struct('PROCESS_INFORMATION')
    flags  = WinAPI::DEBUG_PROCESS
    flags |= WinAPI::DEBUG_ONLY_THIS_PROCESS if not trace_children
    target = target.dup if target.frozen?	# eg ARGV
    h = WinAPI.createprocessa(nil, target, nil, nil, 0, flags, nil, nil, startupinfo, processinfo)
    raise "CreateProcess: #{WinAPI.last_error_msg}" if not h

    set_context(processinfo.dwprocessid, processinfo.dwthreadid)
    @os_process = WinOS::Process.new(processinfo.dwprocessid, processinfo.hprocess)
    @os_thread  = WinOS::Thread.new(processinfo.dwthreadid, processinfo.hthread, @os_process)
    initialize_osprocess
    end

  # called whenever we receive a handle to a new process being debugged, after initialisation of @os_process
  def initialize_osprocess
    initialize_cpu
    initialize_memory
    initialize_disassembler
    end

  def initialize_newpid
    raise "non-existing pid #@pid" if pid and not WinOS.check_process(@pid)
    super()
    # os_process etc wait for CREATE_THREAD_DBGEVT
  end

  def initialize_newtid
    super()
    # os_thread etc wait for CREATE_THREAD_DBGEVT
    @continuecode = WinAPI::DBG_CONTINUE	#WinAPI::DBG_EXCEPTION_NOT_HANDLED
  end

  def initialize_cpu
    # wait until we receive the CREATE_PROCESS_DBGEVT message
    return if not @os_process
    case WinAPI.host_cpu.shortname
    when 'ia32', 'x64'
      @cpu = Ia32.new(os_process.addrsz)
    else
      raise 'unsupported architecture'
    end
  end

  def initialize_memory
    return if not @os_process
    @memory = os_process.memory
  end

  def mappings
    os_process.mappings
  end

  def modules
    os_process.modules
  end

  def list_processes
    WinOS.list_processes
  end

  def list_threads
    os_process.threads
  end

  def check_pid(pid)
    WinOS.check_process(pid)
  end

  def check_tid(tid)
    # dont raise() on the first set_context when os_proc is not set yet
    return true if not os_process
    super(tid)
  end

  def ctx
    if not @ctx
      # swapin_tid => gui.swapin_tid => getreg before we init os_thread in EventCreateThread
      return Hash.new(0) if not os_thread
      @ctx = os_thread.context
      @ctx.update
  end
    @ctx
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

  def do_continue(*a)
    @cpu.dbg_disable_singlestep(self)
    WinAPI.continuedebugevent(@pid, @tid, @continuecode)
  end

  def do_singlestep(*a)
    @cpu.dbg_enable_singlestep(self)
    WinAPI.continuedebugevent(@pid, @tid, @continuecode)
  end

  def update_dbgev(ev)
    # XXX ev is static, copy all necessary values before yielding to something that may call check_target
    set_context ev.dwprocessid, ev.dwthreadid
    invalidate
    @continuecode = WinAPI::DBG_CONTINUE

    # XXX reinterpret ev as struct32/64 depending on os_process.addrsz ?
    case ev.dwdebugeventcode
    when WinAPI::EXCEPTION_DEBUG_EVENT
      st = ev.exception
      str = st.exceptionrecord
      stf = st.dwfirstchance	# non-zero = first chance

      @state = :stopped
      @info = "exception"

      # DWORD ExceptionCode;
      # DWORD ExceptionFlags;
      # struct _EXCEPTION_RECORD *ExceptionRecord;
      # PVOID ExceptionAddress;
      # DWORD NumberParameters;
      # ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
      case str.exceptioncode
      when WinAPI::STATUS_ACCESS_VIOLATION
        if @auto_fix_fs_bug and ctx.fs != 0x3b
          # fix bug in xpsp1 where fs would get a random value in a debugee
          log "wdbg: #{pid}:#{tid} fix fs bug" if $DEBUG
          ctx.fs = 0x3b
          resume_badbreak
          return
  end
        mode = case str.exceptioninformation[0]
               when 0; :r
               when 1; :w
               when 8; :x
               end
        addr = str.exceptioninformation[1]
        evt_exception(:type => 'access violation', :st => str, :firstchance => stf,
                :fault_addr => addr, :fault_access => mode)
      when WinAPI::STATUS_BREAKPOINT
        # we must ack ntdll interrupts on process start
        # but we should not mask process-generated exceptions by default..
        evt_bpx
      when WinAPI::STATUS_SINGLE_STEP
        evt_hwbp_singlestep
      else
        @status_name ||= WinAPI.cp.lexer.definition.keys.grep(/^STATUS_/).
            sort.inject({}) { |h, c| h.update WinAPI.const_get(c) => c }
        type = @status_name[str.exceptioncode] || str.exceptioncode.to_s(16)
        evt_exception(:type => type, :st => str, :firstchance => stf)
  end

    when WinAPI::CREATE_THREAD_DEBUG_EVENT
      st = ev.createthread
      @os_thread ||= WinOS::Thread.new(@tid, st.hthread, os_process)
      @os_thread.teb_base = st.lpthreadlocalbase if st.lpthreadlocalbase.to_i != 0
      evt_newthread(:st => st)

    when WinAPI::CREATE_PROCESS_DEBUG_EVENT
      # XXX 32 vs 64 struct undecidable before we get hprocess..
      st = ev.createprocess
      if not @os_process
        @os_process = WinOS::Process.new(@pid, st.hprocess)
        @os_thread ||= WinOS::Thread.new(@tid, st.hthread, os_process)
        initialize_osprocess
      else
        @os_thread ||= WinOS::Thread.new(@tid, st.hthread, os_process)
  end
      @os_thread.teb_base = st.lpthreadlocalbase if st.lpthreadlocalbase.to_i != 0
      hfile = st.hfile
      evt_newprocess(:st => st)
      WinAPI.closehandle(hfile)

    when WinAPI::EXIT_THREAD_DEBUG_EVENT
      st = ev.exitthread
      evt_endthread(:exitcode => st.dwexitcode)

    when WinAPI::EXIT_PROCESS_DEBUG_EVENT
      st = ev.exitprocess
      evt_endprocess(:exitcode => st.dwexitcode)

    when WinAPI::LOAD_DLL_DEBUG_EVENT
      st = ev.loaddll
      hfile = st.hfile
      evt_loadlibrary(:address => st.lpbaseofdll, :st => st)
      WinAPI.closehandle(hfile)

    when WinAPI::UNLOAD_DLL_DEBUG_EVENT
      st = ev.unloaddll
      evt_unloadlibrary(:address => st.lpbaseofdll)

    when WinAPI::OUTPUT_DEBUG_STRING_EVENT
      st = ev.debugstring
      str = WinAPI.decode_c_ary("__int#{st.funicode != 0 ? 16 : 8}", st.ndebugstringlength, @memory, st.lpdebugstringdata) if st.lpdebugstringdata
      str = str.to_array.pack('C*') rescue str.to_array.pack('v*')
      evt_debugstring(:string => str, :st => str)

    when WinAPI::RIP_EVENT
      st = ev.ripinfo
      evt_ripevent(:st => st)
      end
  end

  def evt_debugstring(info={})
    @state = :stopped
    @info = "debugstring"

    log "Debugstring: #{info[:string].inspect}"

    callback_debugstring[info] if callback_debugstring

    # allow callback to skip this call to continue() by setting info[:nocontinue] = true
    continue unless info[:nocontinue]
  end

  def evt_unloadlibrary(info={})
    @state = :stopped
    @info = "unload library"

    callback_unloadlibrary[info] if callback_unloadlibrary

    continue unless info[:nocontinue]
  end

  def evt_ripevent(info={})
    @state = :stopped
    @info = "rip_event"	# wtf?

    callback_ripevent[info] if callback_ripevent

    continue unless info[:nocontinue]
  end

  def do_check_target
    do_waitfordebug(0)
  end

  def do_wait_target
    do_waitfordebug(WinAPI::INFINITE)
  end

  def do_waitfordebug(timeout)
    @dbg_eventstruct ||= WinAPI.alloc_c_struct('_DEBUG_EVENT')
    if WinAPI.waitfordebugevent(@dbg_eventstruct, timeout) != 0
      update_dbgev(@dbg_eventstruct)
  end
  end

  def break
    return if @state != :running
    if WinAPI.respond_to? :debugbreakprocess
      WinAPI.debugbreakprocess(os_process.handle)
    else
      suspend
  end
        end

  def suspend
    os_thread.suspend
        @state = :stopped
    @info = 'thread suspended'
      end

  def detach
    del_all_breakpoints
    if WinAPI.respond_to? :debugactiveprocessstop
      WinAPI.debugactiveprocessstop(@pid)
    else
      raise 'detach not supported'
    end
    del_pid
  end

  def kill(exitcode=0)
    os_process.terminate(exitcode)
      end

  def pass_current_exception(doit = true)
    @continuecode = (doit ? WinAPI::DBG_EXCEPTION_NOT_HANDLED : WinAPI::DBG_CONTINUE)
  end
end
end
