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
#include "CommonUtils.h"
#include "ntimports.h"

HANDLE CreateObjectDirectory(HANDLE hRoot, LPCWSTR dirname, HANDLE hShadow)
{
	DEFINE_NTDLL(RtlInitUnicodeString);
	DEFINE_NTDLL(NtCreateDirectoryObjectEx);

	OBJECT_ATTRIBUTES obj_attr;
	UNICODE_STRING obj_name;

	if (dirname)
	{
		fRtlInitUnicodeString(&obj_name, dirname);
		InitializeObjectAttributes(&obj_attr, &obj_name, OBJ_CASE_INSENSITIVE, hRoot, nullptr);
	}
	else
	{
		InitializeObjectAttributes(&obj_attr, nullptr, OBJ_CASE_INSENSITIVE, hRoot, nullptr);
	}

	HANDLE h = nullptr;
	NTSTATUS status = fNtCreateDirectoryObjectEx(&h, DIRECTORY_ALL_ACCESS, &obj_attr, hShadow, FALSE);
	if (status == 0)
	{
		return h;
	}
	else
	{
		SetLastError(NtStatusToDosError(status));
		return nullptr;
	}
}

HANDLE OpenObjectDirectory(HANDLE hRoot, LPCWSTR dirname)
{
	DEFINE_NTDLL(RtlInitUnicodeString);
	DEFINE_NTDLL(NtOpenDirectoryObject);

	OBJECT_ATTRIBUTES obj_attr;
	UNICODE_STRING obj_name;

	fRtlInitUnicodeString(&obj_name, dirname);

	InitializeObjectAttributes(&obj_attr, &obj_name, OBJ_CASE_INSENSITIVE, hRoot, nullptr);

	HANDLE h = nullptr;

	NTSTATUS status = fNtOpenDirectoryObject(&h, MAXIMUM_ALLOWED, &obj_attr);
	if (status == 0)
	{
		return h;
	}
	else
	{
		SetLastError(NtStatusToDosError(status));
		return nullptr;
	}
}