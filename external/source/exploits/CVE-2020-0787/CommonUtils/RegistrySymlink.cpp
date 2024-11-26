//  Copyright 2015 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

#include "stdafx.h"
#include <comdef.h>
#include <vector>
#include <sddl.h>
#include <winternl.h>
#include "CommonUtils.h"

#define INTERNAL_REG_OPTION_CREATE_LINK      (0x00000002L)
#define INTERNAL_REG_OPTION_OPEN_LINK        (0x00000100L)

typedef NTSTATUS(__stdcall *fNtCreateKey)(
	PHANDLE KeyHandle,
	ULONG DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG TitleIndex,
	PUNICODE_STRING Class,
	ULONG CreateOptions,
	PULONG Disposition
	);

typedef NTSTATUS (__stdcall *fNtOpenKeyEx)(
	PHANDLE KeyHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG OpenOptions
	);


typedef NTSTATUS(__stdcall *fNtSetValueKey)(
	HANDLE  KeyHandle,
	PUNICODE_STRING  ValueName,
	ULONG  TitleIndex,
	ULONG  Type,
	PVOID  Data,
	ULONG  DataSize
	);

typedef NTSTATUS(__stdcall *fNtDeleteKey)(
	HANDLE KeyHandle
	);

typedef NTSTATUS(__stdcall *fNtClose)(
	HANDLE Handle
	);

FARPROC GetProcAddressNT(LPCSTR lpName);

typedef VOID(NTAPI *fRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

static bstr_t GetUserSid()
{
	HANDLE hToken;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	DWORD dwSize;

	GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);

	std::vector<BYTE> userbuffer(dwSize);

	GetTokenInformation(hToken, TokenUser, &userbuffer[0], dwSize, &dwSize);

	PTOKEN_USER user = reinterpret_cast<PTOKEN_USER>(&userbuffer[0]);

	LPWSTR lpUser;
	bstr_t ret = L"";

	if (ConvertSidToStringSid(user->User.Sid, &lpUser))
	{
		ret = lpUser;
		LocalFree(lpUser);
	}

	return ret;
}

static bstr_t RegPathToNative(LPCWSTR lpPath)
{
	bstr_t regpath = L"\\Registry\\";

	// Already native rooted
	if (lpPath[0] == '\\')
	{
		return lpPath;
	}

	if (_wcsnicmp(lpPath, L"HKLM\\", 5) == 0)
	{
		return regpath + L"Machine\\" + &lpPath[5];
	}
	else if (_wcsnicmp(lpPath, L"HKU\\", 4) == 0)
	{
		return regpath + L"User\\" + &lpPath[4];
	}
	else if (_wcsnicmp(lpPath, L"HKCU\\", 5) == 0)
	{
		return regpath + L"User\\" + GetUserSid() + L"\\" + &lpPath[5];
	}
	else
	{
		DebugPrintf("Registry path %ls must be absolute or start with HKLM, HKU or HKCU\n");
		return L"";
	}
}

bool CreateRegSymlink(LPCWSTR lpSymlink, LPCWSTR lpTarget, bool bVolatile)
{
	bstr_t symlink = RegPathToNative(lpSymlink);
	bstr_t target = RegPathToNative(lpTarget);

	if (symlink.length() == 0 || target.length() == 0)
	{
		return false;
	}

	DebugPrintf("Creating registry link from %ls to %ls\n", symlink.GetBSTR(), target.GetBSTR());

	fNtCreateKey pfNtCreateKey = (fNtCreateKey)GetProcAddressNT("NtCreateKey");
	fNtSetValueKey pfNtSetValueKey = (fNtSetValueKey)GetProcAddressNT("NtSetValueKey");
	fRtlInitUnicodeString pfRtlInitUnicodeString = (fRtlInitUnicodeString)GetProcAddressNT("RtlInitUnicodeString");

	OBJECT_ATTRIBUTES obj_attr;
	UNICODE_STRING name;

	pfRtlInitUnicodeString(&name, symlink);
	InitializeObjectAttributes(&obj_attr, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	HANDLE hKey;
	ULONG disposition;

	NTSTATUS status = pfNtCreateKey(&hKey, KEY_ALL_ACCESS, &obj_attr, 0, nullptr, 
		INTERNAL_REG_OPTION_CREATE_LINK | (bVolatile ? REG_OPTION_VOLATILE : REG_OPTION_NON_VOLATILE), &disposition);

	if (status == 0)
	{
		UNICODE_STRING value_name;

		pfRtlInitUnicodeString(&value_name, L"SymbolicLinkValue");

		status = pfNtSetValueKey(hKey, &value_name, 0, REG_LINK, target.GetBSTR(), target.length() * sizeof(WCHAR));		
		CloseHandle(hKey);

		if (status != 0)
		{
			SetLastError(NtStatusToDosError(status));
			return false;
		}
	}
	else
	{
		SetLastError(NtStatusToDosError(status));
		return false;
	}

	return true;
}

bool DeleteRegSymlink(LPCWSTR lpSymlink)
{
	fNtOpenKeyEx pfNtOpenKeyEx = (fNtOpenKeyEx)GetProcAddressNT("NtOpenKeyEx");
	fNtDeleteKey pfNtDeleteKey = (fNtDeleteKey)GetProcAddressNT("NtDeleteKey");
	fRtlInitUnicodeString pfRtlInitUnicodeString = (fRtlInitUnicodeString)GetProcAddressNT("RtlInitUnicodeString");

	OBJECT_ATTRIBUTES obj_attr;
	UNICODE_STRING name;

	bstr_t symlink = RegPathToNative(lpSymlink);

	if (symlink.length() == 0)
	{
		return false;
	}

	pfRtlInitUnicodeString(&name, symlink);

	InitializeObjectAttributes(&obj_attr, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENLINK, nullptr, nullptr);

	HANDLE hKey;
	NTSTATUS status = pfNtOpenKeyEx(&hKey, DELETE, &obj_attr, 0);
	if (status == 0)
	{
		status = pfNtDeleteKey(hKey);
		CloseHandle(hKey);

		if (status != 0)
		{
			SetLastError(NtStatusToDosError(status));
			return false;
		}
	}
	else
	{
		SetLastError(NtStatusToDosError(status));

		return false;
	}

	return true;
}