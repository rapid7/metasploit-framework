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

HANDLE CreateSymlink(HANDLE root, LPCWSTR linkname, LPCWSTR targetname)
{
	DEFINE_NTDLL(RtlInitUnicodeString);
	DEFINE_NTDLL(NtCreateSymbolicLinkObject);
	
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING name;
	UNICODE_STRING target;

	fRtlInitUnicodeString(&name, linkname);
	fRtlInitUnicodeString(&target, targetname);

	InitializeObjectAttributes(&objAttr, &name, OBJ_CASE_INSENSITIVE, root, nullptr);	

	HANDLE hLink;

	NTSTATUS status = fNtCreateSymbolicLinkObject(&hLink, 
		SYMBOLIC_LINK_ALL_ACCESS, &objAttr, &target);
	if (status == 0)
	{
		//DebugPrintf("Opened Link %ls -> %ls: %p\n", linkname, targetname, hLink);
		return hLink;
	}
	else
	{
		SetLastError(NtStatusToDosError(status));
		return nullptr;
	}
}

HANDLE OpenSymlink(HANDLE root, LPCWSTR linkname)
{
	DEFINE_NTDLL(RtlInitUnicodeString);
	DEFINE_NTDLL(NtOpenSymbolicLinkObject);

	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING name;	

	fRtlInitUnicodeString(&name, linkname);	

	InitializeObjectAttributes(&objAttr, &name, OBJ_CASE_INSENSITIVE, root, nullptr);

	HANDLE hLink;

	NTSTATUS status = fNtOpenSymbolicLinkObject(&hLink,
		SYMBOLIC_LINK_ALL_ACCESS, &objAttr);
	if (status == 0)
	{		
		return hLink;
	}
	else
	{
		SetLastError(NtStatusToDosError(status));
		return nullptr;
	}
}