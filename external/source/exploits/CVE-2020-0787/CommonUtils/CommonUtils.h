#pragma once

#include <Windows.h>
#include <string>

typedef void(__stdcall *console_output)(const char*);

void DebugSetOutput(console_output pout);
void DebugPrintf(const char* lpFormat, ...);
HANDLE CreateSymlink(HANDLE root, LPCWSTR linkname, LPCWSTR targetname);
HANDLE OpenSymlink(HANDLE root, LPCWSTR linkname);
HANDLE CreateObjectDirectory(HANDLE hRoot, LPCWSTR dirname, HANDLE hShadow);
HANDLE OpenObjectDirectory(HANDLE hRoot, LPCWSTR dirname);
std::wstring GetErrorMessage(DWORD dwError);
std::wstring GetErrorMessage();
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
bool CreateRegSymlink(LPCWSTR lpSymlink, LPCWSTR lpTarget, bool bVolatile);
bool DeleteRegSymlink(LPCWSTR lpSymlink);
DWORD NtStatusToDosError(NTSTATUS status);
bool CreateNativeHardlink(LPCWSTR linkname, LPCWSTR targetname);
HANDLE OpenFileNative(LPCWSTR path, HANDLE root, ACCESS_MASK desired_access, ULONG share_access, ULONG open_options);
std::wstring BuildFullPath(const std::wstring& path, bool native);