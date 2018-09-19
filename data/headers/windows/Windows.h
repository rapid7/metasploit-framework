//
// License:
// https://github.com/rapid7/metasploit-framework/blob/master/LICENSE
//

#define MAX_PATH 260
#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000
#define MEM_RESET 0x00080000
#define MEM_RESET_UNDO 0x1000000
#define MEM_LARGE_PAGES 0x20000000
#define MEM_PHYSICAL 0x00400000
#define MEM_TOP_DOWN 0x00100000
#define MEM_WRITE_WATCH 0x00200000
#define PAGE_EXECUTE_READWRITE 0x00000040
#define HEAP_GENERATE_EXCEPTIONS 0x00000004
#define HEAP_NO_SERIALIZE 0x00000001
#define HEAP_REALLOC_IN_PLACE_ONLY 0x00000010
#define HEAP_ZERO_MEMORY 0x00000008
#define STARTF_FORCEONFEEDBACK 0x00000040
#define STARTF_FORCEOFFFEEDBACK 0x00000080
#define STARTF_PREVENTPINNING 0x00002000
#define STARTF_RUNFULLSCREEN 0x00000020
#define STARTF_TITLEISAPPID 0x00001000
#define STARTF_TITLEISLINKNAME 0x00000800
#define STARTF_USECOUNTCHARS 0x00000008
#define STARTF_USEFILLATTRIBUTE 0x00000010
#define STARTF_USEHOTKEY 0x00000200
#define STARTF_USEPOSITION 0x00000004
#define STARTF_USESHOWWINDOW 0x00000001
#define STARTF_USESIZE 0x00000002
#define STARTF_USESTDHANDLES 0x00000100
#define GW_CHILD 5
#define GW_ENABLEDPOPUP 6
#define GW_HWNDFIRST 0
#define GW_HWNDLAST 1
#define GW_HWNDNEXT 2
#define GW_OWNER 4
#define MB_ABORTRETRYIGNORE 0x00000002L
#define MB_CANCELTRYCONTINUE 0x00000006L
#define MB_HELP 0x00004000L
#define MB_OK 0x00000000L
#define MB_OKCANCEL 0x00000001L
#define MB_RETRYCANCEL 0x00000005L
#define MB_YESNO 0x00000004L
#define MB_YESNOCANCEL 0x00000003L
#define MB_ICONEXCLAMATION 0x00000030L
#define MB_ICONWARNING 0x00000030L
#define MB_ICONINFORMATION 0x00000040L
#define MB_ICONASTERISK 0x00000040L
#define MB_ICONQUESTION 0x00000020L
#define MB_ICONSTOP 0x00000010L
#define MB_ICONERROR 0x00000010L
#define MB_ICONHAND 0x00000010L
#define MB_DEFBUTTON1 0x00000000L
#define MB_DEFBUTTON2 0x00000100L
#define MB_DEFBUTTON3 0x00000200L
#define MB_DEFBUTTON4 0x00000300L
#define MB_APPLMODAL 0x00000000L
#define MB_SYSTEMMODAL 0x00001000L
#define MB_TASKMODAL 0x00002000L
#define MB_DEFAULT_DESKTOP_ONLY 0x00020000L
#define MB_RIGHT 0x00080000L
#define MB_RTLREADING 0x00100000L
#define MB_SETFOREGROUND 0x00010000L
#define MB_TOPMOST 0x00040000L
#define MB_SERVICE_NOTIFICATION 0x00200000L
#define IDABORT 3
#define IDCANCEL 2
#define IDCONTINUE 11
#define IDIGNORE 5
#define IDNO 7
#define IDOK 1
#define IDRETRY 4
#define IDTRYAGAIN 10
#define IDYES 6
#define HEAP_CREATE_ENABLE_EXECUTE 0x00040000
#define SC_MANAGER_ALL_ACCESS 0xf003f
#define SC_MANAGER_CONNECT 1
#define SC_MANAGER_CREATE_SERVICE 2
#define SC_MANAGER_ENUMERATE_SERVICE 4
#define SC_MANAGER_LOCK 8
#define SC_MANAGER_QUERY_LOCK_STATUS 16
#define SC_MANAGER_MODIFY_BOOT_CONFIG 32
#define SERVICE_NO_CHANGE (-1)
#define SERVICE_STOPPED 1
#define SERVICE_START_PENDING 2
#define SERVICE_STOP_PENDING  3
#define SERVICE_RUNNING 4
#define SERVICE_CONTINUE_PENDING  5
#define SERVICE_PAUSE_PENDING 6
#define SERVICE_PAUSED  7
#define SERVICE_ACCEPT_STOP 1
#define SERVICE_ACCEPT_PAUSE_CONTINUE 2
#define SERVICE_ACCEPT_SHUTDOWN 4
#define SERVICE_CONTROL_STOP  1
#define SERVICE_CONTROL_PAUSE 2
#define SERVICE_CONTROL_CONTINUE  3
#define SERVICE_CONTROL_INTERROGATE 4
#define SERVICE_CONTROL_SHUTDOWN  5
#define SERVICE_ACTIVE 1
#define SERVICE_INACTIVE 2
#define SERVICE_STATE_ALL 3
#define SERVICE_QUERY_CONFIG 1
#define SERVICE_CHANGE_CONFIG 2
#define SERVICE_QUERY_STATUS 4
#define SERVICE_ENUMERATE_DEPENDENTS 8
#define SERVICE_START 16
#define SERVICE_STOP 32
#define SERVICE_PAUSE_CONTINUE 64
#define SERVICE_INTERROGATE 128
#define SERVICE_USER_DEFINED_CONTROL 256
#define SERVICE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SERVICE_QUERY_CONFIG|SERVICE_CHANGE_CONFIG|SERVICE_QUERY_STATUS|SERVICE_ENUMERATE_DEPENDENTS|SERVICE_START|SERVICE_STOP|SERVICE_PAUSE_CONTINUE|SERVICE_INTERROGATE|SERVICE_USER_DEFINED_CONTROL)
#define GHND 0x0042
#define GMEM_FIXED 0x0000
#define GMEM_MOVEABLE 0x0002
#define GMEM_ZEROINIT 0x0040
#define GPTR 0x0040
#define WH_CALLWNDPROC 4
#define WH_CALLWNDPROCRET 12
#define WH_CBT 5
#define WH_DEBUG 9
#define WH_FOREGROUNDIDLE 11
#define WH_GETMESSAGE 3
#define WH_JOURNALPLAYBACK 1
#define WH_JOURNALRECORD 0
#define WH_KEYBOARD 2
#define WH_KEYBOARD_LL 13
#define WH_MOUSE 7
#define WH_MOUSE_LL 14
#define WH_MSGFILTER -1
#define WH_SHELL 10
#define WH_SYSMSGFILTER 6
#define GENERIC_READ 0x80000000
#define GENERIC_WRITE 0x40000000
#define GENERIC_EXECUTE 0x20000000
#define GENERIC_ALL 0x10000000
#define FILE_SHARE_READ 0x00000001
#define FILE_SHARE_WRITE 0x00000002
#define FILE_SHARE_DELETE 0x00000004
#define CREATE_NEW 1
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3
#define OPEN_ALWAYS 4
#define TRUNCATE_EXISTING 5
#define FILE_ATTRIBUTE_READONLY 0x00000001
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#define FILE_ATTRIBUTE_TEMPORARY 0x00000100
#define FILE_FLAG_WRITE_THROUGH 0x80000000
#define FILE_FLAG_NO_BUFFERING 0x20000000
#define FILE_FLAG_RANDOM_ACCESS 0x10000000
#define FILE_FLAG_SEQUENTIAL_SCAN 0x08000000
#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000
#define FILE_FLAG_OVERLAPPED 0x40000000
#define FILE_ATTRIBUTE_HIDDEN 0x00000002
#define FILE_ATTRIBUTE_SYSTEM 0x00000004
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010
#define FILE_ATTRIBUTE_ARCHIVE 0x00000020
#define FILE_ATTRIBUTE_DEVICE 0x00000040
#define ERROR_FILE_NOT_FOUND 2L
#define ERROR_NO_MORE_FILES 18L
#define INVALID_HANDLE_VALUE ((HANDLE) -1)
#define INVALID_FILE_SIZE ((DWORD)0xFFFFFFFF)
#define FILE_NAME_NORMALIZED 0x0
#define FILE_NAME_OPENED 0x8
#define VOLUME_NAME_DOS 0x0
#define VOLUME_NAME_GUID 0x1
#define VOLUME_NAME_NONE 0x4
#define VOLUME_NAME_NT 0x2
#define SERVICE_FILE_SYSTEM_DRIVER 0x00000002
#define SERVICE_KERNEL_DRIVER 0x00000001
#define SERVICE_WIN32_OWN_PROCESS 0x00000010
#define SERVICE_WIN32_SHARE_PROCESS 0x00000020
#define SERVICE_USER_OWN_PROCESS 0x00000050
#define SERVICE_USER_SHARE_PROCESS 0x00000060
#define SERVICE_INTERACTIVE_PROCESS 0x00000100
#define SERVICE_CONTINUE_PENDING 0x00000005
#define SERVICE_PAUSE_PENDING 0x00000006
#define SERVICE_PAUSED 0x00000007
#define SERVICE_RUNNING 0x00000004
#define SERVICE_START_PENDING 0x00000002
#define SERVICE_STOP_PENDING 0x00000003
#define SERVICE_STOPPED 0x00000001
#define SERVICE_AUTO_START 0x00000002
#define SERVICE_BOOT_START 0x00000000
#define SERVICE_DEMAND_START 0x00000003
#define SERVICE_DISABLED 0x00000004
#define SERVICE_SYSTEM_START 0x00000001
#define SERVICE_ERROR_CRITICAL 0x00000003
#define SERVICE_ERROR_IGNORE 0x00000000
#define SERVICE_ERROR_NORMAL 0x00000001
#define SERVICE_ERROR_SEVERE 0x00000002
#define SERVICE_DRIVER 0x0000000B
#define SERVICE_FILE_SYSTEM_DRIVER 0x00000002
#define SERVICE_KERNEL_DRIVER 0x00000001
#define SERVICE_WIN32 0x00000030
#define SERVICE_WIN32_OWN_PROCESS 0x00000010
#define SERVICE_WIN32_SHARE_PROCESS 0x00000020
#define MAKEWORD(a,b) ((WORD)(((BYTE)(a))|(((WORD)((BYTE)(b)))<<8)))
#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))
#define ZeroMemory RtlZeroMemory

typedef struct _SECURITY_ATTRIBUTES {
  DWORD nLength;
  LPVOID lpSecurityDescriptor;
  BOOL bInheritHandle;
} SECURITY_ATTRIBUTES , *LPSECURITY_ATTRIBUTES;

typedef struct _LPTHREAD_START_ROUTINE {
  LPVOID lpThreadParameter;
} LPTHREAD_START_ROUTINE, *LPTHREAD_START_ROUTINE;

typedef struct _STARTUPINFO {
  DWORD  cb;
  LPTSTR lpReserved;
  LPTSTR lpDesktop;
  LPTSTR lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFO, *LPSTARTUPINFO;

typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
} PROCESS_INFORMATION, *LPPROCESS_INFORMATION;

typedef struct _OVERLAPPED {
  ULONG_PTR Internal;
  ULONG_PTR InternalHigh;
  union {
    struct {
      DWORD Offset;
      DWORD OffsetHigh;
    };
    PVOID  Pointer;
  };
  HANDLE    hEvent;
} OVERLAPPED, *LPOVERLAPPED;

typedef DWORD SERVICE_STATUS_HANDLE;

typedef enum _SC_ENUM_TYPE {
        SC_ENUM_PROCESS_INFO = 0
} SC_ENUM_TYPE;

typedef enum _HEAP_INFORMATION_CLASS {
  HeapCompatibilityInformation = 0,
  HeapEnableTerminationOnCorruption = 1
} HEAP_INFORMATION_CLASS;

typedef struct _FILETIME {
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
} FILETIME, *PFILETIME;

typedef struct _WIN32_FIND_DATA {
  DWORD    dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD    nFileSizeHigh;
  DWORD    nFileSizeLow;
  DWORD    dwReserved0;
  DWORD    dwReserved1;
  TCHAR    cFileName[MAX_PATH];
  TCHAR    cAlternateFileName[14];
} WIN32_FIND_DATA, *PWIN32_FIND_DATA, *LPWIN32_FIND_DATA;

typedef struct tagPOINT {
  LONG x;
  LONG y;
} POINT, *PPOINT;

typedef struct tagMSG {
  HWND   hwnd;
  UINT   message;
  WPARAM wParam;
  LPARAM lParam;
  DWORD  time;
  POINT  pt;
} MSG, *PMSG, *LPMSG;

typedef struct _BY_HANDLE_FILE_INFORMATION {
  DWORD    dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD    dwVolumeSerialNumber;
  DWORD    nFileSizeHigh;
  DWORD    nFileSizeLow;
  DWORD    nNumberOfLinks;
  DWORD    nFileIndexHigh;
  DWORD    nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION, *PBY_HANDLE_FILE_INFORMATION, *LPBY_HANDLE_FILE_INFORMATION;

typedef struct _SERVICE_STATUS {
  DWORD dwServiceType;
  DWORD dwCurrentState;
  DWORD dwControlsAccepted;
  DWORD dwWin32ExitCode;
  DWORD dwServiceSpecificExitCode;
  DWORD dwCheckPoint;
  DWORD dwWaitHint;
} SERVICE_STATUS, *LPSERVICE_STATUS;

typedef struct _ENUM_SERVICE_STATUS {
  LPTSTR         lpServiceName;
  LPTSTR         lpDisplayName;
  SERVICE_STATUS ServiceStatus;
} ENUM_SERVICE_STATUS, *LPENUM_SERVICE_STATUS;

typedef struct _GUID {
  DWORD Data1;
  WORD  Data2;
  WORD  Data3;
  BYTE  Data4[8];
} GUID;

typedef VOID (CALLBACK *LPOVERLAPPED_COMPLETION_ROUTINE)(DWORD,DWORD,LPOVERLAPPED);

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation                      = 0,
    ProcessQuotaLimits                           = 1,
    ProcessIoCounters                            = 2,
    ProcessVmCounters                            = 3,
    ProcessTimes                                 = 4,
    ProcessBasePriority                          = 5,
    ProcessRaisePriority                         = 6,
    ProcessDebugPort                             = 7,
    ProcessExceptionPort                         = 8,
    ProcessAccessToken                           = 9,
    ProcessLdtInformation                        = 10,
    ProcessLdtSize                               = 11,
    ProcessDefaultHardErrorMode                  = 12,
    ProcessIoPortHandlers                        = 13,
    ProcessPooledUsageAndLimits                  = 14,
    ProcessWorkingSetWatch                       = 15,
    ProcessUserModeIOPL                          = 16,
    ProcessEnableAlignmentFaultFixup             = 17,
    ProcessPriorityClass                         = 18,
    ProcessWx86Information                       = 19,
    ProcessHandleCount                           = 20,
    ProcessAffinityMask                          = 21,
    ProcessPriorityBoost                         = 22,
    ProcessDeviceMap                             = 23,
    ProcessSessionInformation                    = 24,
    ProcessForegroundInformation                 = 25,
    ProcessWow64Information                      = 26,
    ProcessImageFileName                         = 27,
    ProcessLUIDDeviceMapsEnabled                 = 28,
    ProcessBreakOnTermination                    = 29,
    ProcessDebugObjectHandle                     = 30,
    ProcessDebugFlags                            = 31,
    ProcessHandleTracing                         = 32,
    ProcessIoPriority                            = 33,
    ProcessExecuteFlags                          = 34,
    ProcessTlsInformation                        = 35,
    ProcessCookie                                = 36,
    ProcessImageInformation                      = 37,
    ProcessCycleTime                             = 38,
    ProcessPagePriority                          = 39,
    ProcessInstrumentationCallback               = 40,
    ProcessThreadStackAllocation                 = 41,
    ProcessWorkingSetWatchEx                     = 42,
    ProcessImageFileNameWin32                    = 43,
    ProcessImageFileMapping                      = 44,
    ProcessAffinityUpdateMode                    = 45,
    ProcessMemoryAllocationMode                  = 46,
    ProcessGroupInformation                      = 47,
    ProcessTokenVirtualizationEnabled            = 48,
    ProcessOwnerInformation                      = 49,
    ProcessWindowInformation                     = 50,
    ProcessHandleInformation                     = 51,
    ProcessMitigationPolicy                      = 52,
    ProcessDynamicFunctionTableInformation       = 53,
    ProcessHandleCheckingMode                    = 54,
    ProcessKeepAliveCount                        = 55,
    ProcessRevokeFileHandles                     = 56,
    ProcessWorkingSetControl                     = 57,
    ProcessHandleTable                           = 58,
    ProcessCheckStackExtentsMode                 = 59,
    ProcessCommandLineInformation                = 60,
    ProcessProtectionInformation                 = 61,
    ProcessMemoryExhaustion                      = 62,
    ProcessFaultInformation                      = 63,
    ProcessTelemetryIdInformation                = 64,
    ProcessCommitReleaseInformation              = 65,
    ProcessReserved1Information                  = 66,
    ProcessReserved2Information                  = 67,
    ProcessSubsystemProcess                      = 68,
    ProcessInPrivate                             = 70,
    ProcessRaiseUMExceptionOnInvalidHandleClose  = 71,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _FINDEX_INFO_LEVELS { 
  FindExInfoStandard,
  FindExInfoBasic,
  FindExInfoMaxInfoLevel
} FINDEX_INFO_LEVELS;

typedef enum _FINDEX_SEARCH_OPS { 
  FindExSearchNameMatch,
  FindExSearchLimitToDirectories,
  FindExSearchLimitToDevices
} FINDEX_SEARCH_OPS;

WINAPI void OutputDebugString __attribute__((dllimport))(LPCTSTR);
WINAPI HGLOBAL GlobalAlloc __attribute__((dllimport))(UINT, size_t);
WINAPI LPVOID GlobalLock __attribute__((dllimport))(HGLOBAL);
WINAPI BOOL GlobalUnlock __attribute__((dllimport))(HGLOBAL);
WINAPI HGLOBAL GlobalReAlloc __attribute__((dllimport))(HGLOBAL, size_t, UINT);
WINAPI HGLOBAL GlobalFree __attribute__((dllimport))(HGLOBAL);
WINAPI DWORD GetLastError __attribute__((dllimport))(void);
WINAPI LPVOID VirtualAlloc __attribute__((dllimport))(LPVOID, size_t, DWORD, DWORD);
WINAPI LPVOID VirtualAllocEx __attribute__((dllimport))(HANDLE, LPVOID, size_t, DWORD, DWORD);
WINAPI BOOL VirtualProtect __attribute__((dllimport))(LPVOID, size_t, DWORD, PDWORD);
WINAPI BOOL VirtualProtectEx __attribute__((dllimport))(HANDLE, LPVOID, size_t, DWORD, PDWORD);
WINAPI HANDLE GetProcessHeap __attribute__((dllimport))(void);
WINAPI DWORD GetProcessHeaps __attribute__((dllimport))(DWORD, PHANDLE);
WINAPI HANDLE HeapCreate __attribute__((dllimport))(DWORD, size_t, size_t);
WINAPI LPVOID HeapAlloc __attribute__((dllimport))(HANDLE, DWORD, size_t);
WINAPI size_t HeapSize __attribute__((dllimport))(HANDLE, DWORD, LPCVOID);
WINAPI LPVOID HeapreAlloc __attribute__((dllimport))(HANDLE, DWORD, LPVOID, size_t);
WINAPI BOOL HeapFree __attribute__((dllimport))(HANDLE, DWORD, LPVOID);
WINAPI BOOL HeapQueryInformation __attribute__((dllimport))(HANDLE, HEAP_INFORMATION_CLASS, PVOID, size_t, PSIZE_T);
WINAPI BOOL HeapSetInformation __attribute__((dllimport))(HANDLE, HEAP_INFORMATION_CLASS, PVOID, size_t);
WINAPI BOOL VirtualFreeEx __attribute__((dllimport))(HANDLE, LPVOID, size_t, DWORD);
WINAPI void MoveMemory __attribute__((dllimport))(PVOID, void*, size_t);
WINAPI BOOL WriteProcessMemory __attribute__((dllimport))(HANDLE, LPVOID, LPCVOID, size_t, size_t*);
WINAPI BOOL ReadProcessMemory __attribute__((dllimport))(HANDLE, LPCVOID, LPVOID, size_t, size_t*);
WINAPI HANDLE CreateThread __attribute__((dllimport))(LPSECURITY_ATTRIBUTES, size_t, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );
WINAPI HANDLE CreateRemoteThread __attribute__((dllimport))(HANDLE, LPSECURITY_ATTRIBUTES, size_t, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );
WINAPI DWORD GetProcessId __attribute__((dllimport))(HANDLE);
WINAPI BOOL CreateProcess __attribute__((dllimport))(LPCTSTR, LPTSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCTSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION);
WINAPI BOOL CreateProcessAsUser __attribute__((dllimport))(HANDLE, LPCTSTR, LPTSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCTSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION);
WINAPI HANDLE OpenProcess __attribute__((dllimport))(DWORD, BOOL, DWORD);
WINAPI void ExitProcess __attribute__((dllimport))(UINT);
WINAPI BOOL TerminateProcess __attribute__((dllimport))(UINT);
WINAPI DWORD GetTickCount __attribute__((dllimport))(void);
WINAPI void Sleep __attribute__((dllimport))(DWORD);
WINAPI UINT WinExec __attribute__((dllimport))(LPCSTR, UINT);
WINAPI DWORD WaitForSingleObject __attribute__((dllimport))(HANDLE, DWORD);
WINAPI FARPROC GetProcAddress __attribute__((dllimport))(HMODULE, LPCSTR);
WINAPI HMODULE LoadLibrary __attribute__((dllimport))(LPCTSTR);
WINAPI HMODULE GetModuleHandle __attribute__((dllimport))(LPCTSTR);
WINAPI HANDLE CreateFile __attribute__((dllimport))(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINAPI BOOL GetFileInformationByHandle __attribute__((dllimport))(HANDLE, LPBY_HANDLE_FILE_INFORMATION);
WINAPI DWORD GetFullPathName __attribute__((dllimport))(LPCTSTR, DWORD, LPTSTR, LPTSTR*);
WINAPI DWORD GetFileType __attribute__((dllimport))(HANDLE);
WINAPI BOOL MoveFile __attribute__((dllimport))(LPCTSTR, LPCTSTR);
WINAPI BOOL DeleteFile __attribute__((dllimport))(LPCTSTR);
WINAPI BOOL CopyFile __attribute__((dllimport))(LPCTSTR, LPCTSTR, BOOL);
WINAPI BOOL WriteFile __attribute__((dllimport))(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINAPI BOOL ReadFile __attribute__((dllimport))(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINAPI BOOL ReadFileEx __attribute__((dllimport))(HANDLE, LPVOID, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE);
WINAPI DWORD GetFileSize __attribute__((dllimport))(HANDLE, LPDWORD);
WINAPI DWORD GetTempPath __attribute__((dllimport))(DWORD, LPTSTR);
WINAPI UINT GetTempFileName __attribute__((dllimport))(LPCTSTR, LPCTSTR, UINT, LPTSTR);
WINAPI DWORD GetShortPathName __attribute__((dllimport))(LPCTSTR, LPTSTR, DWORD);
WINAPI DWORD GetLongPathName __attribute__((dllimport))(LPCTSTR, LPTSTR, DWORD);
WINAPI INT GetExpandedName __attribute__((dllimport))(LPTSTR, LPTSTR);
WINAPI DWORD GetFinalPathNameByHandle __attribute__((dllimport))(HANDLE, LPTSTR, DWORD, DWORD);
WINAPI BOOL LockFile __attribute__((dllimport))(HANDLE, DWORD, DWORD, DWORD, DWORD);
WINAPI BOOL UnlockFile __attribute__((dllimport))(HANDLE, DWORD, DWORD, DWORD, DWORD);
WINAPI BOOL UnlockFileEx __attribute__((dllimport))(HANDLE, DWORD, DWORD, DWORD, LPOVERLAPPED);
WINAPI BOOL FreeLibrary __attribute__((dllimport))(HMODULE);
WINAPI DWORD GetModuleFileName __attribute__((dllimport))(HMODULE, LPTSTR, DWORD);
WINAPI BOOL CloseHandle __attribute__((dllimport))(HANDLE);
WINAPI void DebugBreak __attribute__((dllimport))(void);
WINAPI HWND FindWindow __attribute__((dllimport))(LPCTSTR, LPCTSTR);
WINAPI HWND FindWindowEx __attribute__((dllimport))(HWND, HWND, LPCTSTR, LPCTSTR);
WINAPI HWND GetWindow __attribute__((dllimport))(HWND, UINT);
WINAPI HWND GetForegroundWindow __attribute__((dllimport))(void);
WINAPI BOOL SetForegroundWindow __attribute__((dllimport))(HWND);
WINAPI HWND GetDesktopWindow __attribute__((dllimport))(void);
WINAPI HWND SetActiveWindow __attribute__((dllimport))(HWND);
WINAPI BOOL IsWindowEnabled __attribute__((dllimport))(HWND);
WINAPI HWND SetFocus __attribute__((dllimport))(HWND);
WINAPI BOOL MoveWindow __attribute__((dllimport))(HWND, int, int, int, int, BOOL);
WINAPI int MessageBox __attribute__((dllimport))(HWND, LPCTSTR, LPCTSTR, UINT);
WINAPI BOOL Beep __attribute__((dllimport))(DWORD, DWORD);
WINAPI BOOL CreateDirectory __attribute__((dllimport))(LPCTSTR, LPSECURITY_ATTRIBUTES);
WINAPI HANDLE CreateFileMapping __attribute__((dllimport))(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCTSTR);
WINAPI LPVOID MapViewOfFile __attribute__((dllimport))(HANDLE, DWORD, DWORD, DWORD, size_t);
WINAPI LPVOID MapViewOfFileEx __attribute__((dllimport))(HANDLE, DWORD, DWORD, DWORD, size_t, LPVOID);
WINAPI BOOL FindClose __attribute__((dllimport))(HANDLE);
WINAPI HANDLE FindFirstFile __attribute__((dllimport))(LPCTSTR, LPWIN32_FIND_DATA);
WINAPI HANDLE FindFirstFileEx __attribute__((dllimport))(LPCTSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);
WINAPI BOOL FindNextFile __attribute__((dllimport))(HANDLE, LPWIN32_FIND_DATA);
WINAPI HANDLE GetCurrentProcess __attribute__((dllimport))(void);
WINAPI HANDLE GetCurrentThread __attribute__((dllimport))(void);
WINAPI LRESULT CallNextHookEx __attribute__((dllimport))(HHOOK, int, WPARAM, LPARAM);
WINAPI BOOL GetMessage __attribute__((dllimport))(LPMSG, HWND, UINT, UINT);
WINAPI BOOL PostMessage __attribute__((dllimport))(HWND, UINT, WPARAM, LPARAM);
WINAPI LRESULT SendMessage __attribute__((dllimport))(HWND, UINT, WPARAM, LPARAM);
WINAPI SC_HANDLE OpenSCManager __attribute__((dllimport))(LPCTSTR, LPCTSTR, DWORD);
WINAPI BOOL StartService __attribute__((dllimport))(SC_HANDLE, DWORD, LPCTSTR*);
WINAPI BOOL SetServiceStatus __attribute__((dllimport))(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS);
WINAPI SC_HANDLE CreateService __attribute__((dllimport))(SC_HANDLE, LPCTSTR, LPCTSTR, DWORD, DWORD, DWORD, DWORD, LPCTSTR, LPCTSTR, LPDWORD, LPCTSTR, LPCTSTR, LPCTSTR);
WINAPI SC_HANDLE OpenService __attribute__((dllimport))(SC_HANDLE, LPCTSTR, DWORD);
WINAPI BOOL ChangeServiceConfig __attribute__((dllimport))(SC_HANDLE, DWORD, DWORD, DWORD, LPCTSTR, LPCTSTR, LPDWORD, LPCTSTR, LPCTSTR, LPCTSTR, LPCTSTR);
WINAPI BOOL DeleteService __attribute__((dllimport))(SC_HANDLE);
WINAPI BOOL EnumServicesStatus __attribute__((dllimport))(SC_HANDLE, DWORD, DWORD, LPENUM_SERVICE_STATUS, DWORD, LPDWORD, LPDWORD, LPDWORD);
WINAPI BOOL EnumServicesStatusEx __attribute__((dllimport))(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCTSTR);
WINAPI BOOL CloseServiceHandle __attribute__((dllimport))(SC_HANDLE);
WINAPI BOOL ControlService __attribute__((dllimport))(SC_HANDLE, DWORD, LPSERVICE_STATUS);
WINAPI BOOL GetServiceDisplayName __attribute__((dllimport))(SC_HANDLE, LPCTSTR, LPTSTR, LPDWORD);
WINAPI BOOL GetServiceKeyName __attribute__((dllimport))(SC_HANDLE, LPCTSTR, LPTSTR, LPDWORD);
WINAPI BOOL QueryServiceStatus __attribute__((dllimport))(SC_HANDLE, LPSERVICE_STATUS);
WINAPI BOOL OpenClipboard __attribute__((dllimport))(HWND);
WINAPI HANDLE SetClipboardData __attribute__((dllimport))(UINT, HANDLE);
WINAPI HANDLE GetClipboardData __attribute__((dllimport))(UINT);
WINAPI BOOL EmptyClipboard __attribute__((dllimport))(void);
WINAPI BOOL CloseClipboard __attribute__((dllimport))(void);
WINAPI LONG RegSetValueEx __attribute__((dllimport))(HKEY, LPCTSTR, DWORD, DWORD, const BYTE*, DWORD);
WINAPI LONG RegOpenCurrentUser __attribute__((dllimport))(REGSAM, PHKEY);
WINAPI LONG RegDeleteValue __attribute__((dllimport))(HKEY, LPCTSTR);
WINAPI LONG RegOpenKey __attribute__((dllimport))(HKEY, LPCTSTR, PHKEY);
WINAPI LONG RegQueryValueEx __attribute__((dllimport))(HKEY, LPCTSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
WINAPI LONG RegCloseKey __attribute__((dllimport))(HKEY);
WINAPI LONG RegCreateKeyEx __attribute__((dllimport))(HKEY, LPCTSTR, DWORD, LPTSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
WINAPI HHOOK SetWindowHookEx __attribute__((dllimport))(int, HOOKPROC, HINSTANCE, DWORD);
WINAPI BOOL UnhookWindowsHookEx __attribute__((dllimport))(HHOOK);
WINAPI BOOL IsDebuggerPresent __attribute__((dllimport))(void);
WINAPI BOOL CheckRemoteDebuggerPresent __attribute__((dllimport))(HANDLE, PBOOL);
WINAPI NTSTATUS NtQueryInformationProcess __attribute__((dllimport))(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
WINAPI void SetLastError __attribute__((dllimport))(DWORD);
