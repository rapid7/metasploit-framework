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
#include "ntimports.h"
#include "typed_buffer.h"
#include <string>

std::wstring BuildFullPath(const std::wstring& path, bool native)
{
	std::wstring ret;
	WCHAR buf[MAX_PATH];

	if (native)
	{
		ret = L"\\??\\";
	}

	if (GetFullPathName(path.c_str(), MAX_PATH, buf, nullptr) > 0)
	{
		ret += buf;
	}
	else
	{
		ret += path;
	}

	return ret;
}

FARPROC GetProcAddressNT(LPCSTR lpName)
{
	return GetProcAddress(GetModuleHandleW(L"ntdll"), lpName);
}

HANDLE OpenFileNative(LPCWSTR path, HANDLE root, ACCESS_MASK desired_access, ULONG share_access, ULONG open_options)
{
	UNICODE_STRING name = { 0 };
	OBJECT_ATTRIBUTES obj_attr = { 0 };

	DEFINE_NTDLL(RtlInitUnicodeString);
	DEFINE_NTDLL(NtOpenFile);

	if (path)
	{
		fRtlInitUnicodeString(&name, path);
		InitializeObjectAttributes(&obj_attr, &name, OBJ_CASE_INSENSITIVE, root, nullptr);
	}
	else
	{
		InitializeObjectAttributes(&obj_attr, nullptr, OBJ_CASE_INSENSITIVE, root, nullptr);
	}

	HANDLE h = nullptr;
	IO_STATUS_BLOCK io_status = { 0 };
	NTSTATUS status = fNtOpenFile(&h, desired_access, &obj_attr, &io_status, share_access, open_options);
	if (NT_SUCCESS(status))
	{
		return h;
	}
	else
	{
		return nullptr;
	}
}

bool CreateNativeHardlink(LPCWSTR linkname, LPCWSTR targetname)
{
	std::wstring full_linkname = BuildFullPath(linkname, true);
	size_t len = full_linkname.size() * sizeof(WCHAR);

	typed_buffer_ptr<FILE_LINK_INFORMATION> link_info(sizeof(FILE_LINK_INFORMATION) + len - sizeof(WCHAR));

	memcpy(&link_info->FileName[0], full_linkname.c_str(), len);
	link_info->ReplaceIfExists = TRUE;
	link_info->FileNameLength = len;

	std::wstring full_targetname = BuildFullPath(targetname, true);
	
	HANDLE hFile = OpenFileNative(full_targetname.c_str(), nullptr, MAXIMUM_ALLOWED, FILE_SHARE_READ, 0);
	if (hFile)
	{
		DEFINE_NTDLL(ZwSetInformationFile);
		IO_STATUS_BLOCK io_status = { 0 };

		NTSTATUS status = fZwSetInformationFile(hFile, &io_status, link_info, link_info.size(), FileLinkInformation);
		CloseHandle(hFile);
		if (NT_SUCCESS(status))
		{
			return true;
		}
	}
	
	return false;	
}