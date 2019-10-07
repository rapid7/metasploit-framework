#ifndef _KERNEL_UTIL
#define _KERNEL_UTIL

typedef BOOL (WINAPI *FuncCreateProcess) (
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);

typedef BOOL (WINAPI *FuncSetHandleInformation)
(
  HANDLE hObject,
  DWORD dwMask,
  DWORD dwFlags
);

typedef BOOL (WINAPI *FuncReadFile)
(
  HANDLE hFile,
  LPVOID lpBuffer,
  DWORD nNumberOfBytesToRead,
  LPDWORD lpNumberOfBytesToRead,
  LPOVERLAPPED lpOverlapped
);

typedef BOOL (WINAPI *FuncWriteFile)
(
  HANDLE hFile,
  LPCVOID lpBuffer,
  DWORD nNumberOfBytesToWrite,
  LPDWORD lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);

typedef BOOL (WINAPI *FuncPeekNamedPipe)
(
  HANDLE hNamedPipe,
  LPVOID lpBuffer,
  DWORD nBufferSize,
  LPDWORD nBytesRead,
  LPDWORD lpTotalBytesAvailable,
  LPDWORD lpBytesLeftThisMessage
);

typedef BOOL (WINAPI *FuncCreatePipe)
(
  PHANDLE hReadPipe,
  PHANDLE hWritePipe,
  LPSECURITY_ATTRIBUTES lpPipeAttributes,
  DWORD nSize
);

typedef BOOL (WINAPI *FuncCloseHandle)
(
  HANDLE hObject
);

typedef HGLOBAL (WINAPI *FuncGlobalAlloc)
(
  UINT uFlags,
  SIZE_T dwBytes
);

typedef HGLOBAL (WINAPI *FuncGlobalFree)
(
  HGLOBAL hMem
);

typedef HANDLE (WINAPI *FuncHeapCreate)
(
  DWORD flOptions,
  SIZE_T dwInitialize,
  SIZE_T dwMaximumSize
);

typedef LPVOID (WINAPI *FuncHeapAlloc)
(
  HANDLE hHeap,
  DWORD dwFlags,
  SIZE_T dwBytes
);

typedef VOID (WINAPI *FuncSleep)
(
  DWORD dwMilliseconds
);

typedef HANDLE (WINAPI *FuncGetCurrentProcess) ();

typedef BOOL (WINAPI *FuncGetExitCodeProcess)
(
  HANDLE hProcess,
  LPDWORD lpExitCode
);

typedef VOID (WINAPI *FuncExitProcess)
(
  UINT uExitCode
);

typedef BOOL (WINAPI *FuncCloseHandle)
(
  HANDLE hObject
);

typedef BOOL (WINAPI *FuncVirtualProtect)
(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD flNewProtect,
  PDWORD lpflOldProtect
);

typedef LPVOID (WINAPI *FuncVirtualAlloc)
(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD flAllocationType,
  DWORD flProtect
);

typedef BOOL (WINAPI *FuncVirtualFree)
(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD dwFreeType
);

#endif
