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
#include "FileSymlink.h"

#include <vector>
#include "ReparsePoint.h"
#include "CommonUtils.h"

FileSymlink::FileSymlink(bool permanent) 
	: m_created_junction(false), m_hlink(nullptr), m_permanent(permanent)
{
}

FileSymlink::FileSymlink() : FileSymlink(false)
{
}

FileSymlink::~FileSymlink()
{
	if (!m_permanent)
	{
		if (m_hlink)
		{
			CloseHandle(m_hlink);
		}

		if (m_created_junction)
		{
			RemoveDirectory(m_junctiondir);
		}
	}
}

bstr_t GetNativePath(LPCWSTR name, PBOOL isnative)
{
	if (name[0] == '@')
	{
		*isnative = TRUE;
		return name + 1;
	}
	else
	{
		*isnative = FALSE;
		std::vector<WCHAR> buf(32 * 1024);

		if (GetFullPathNameW(name, buf.size(), &buf[0], nullptr) == 0)
		{			
			return L"";
		}

		return &buf[0];
	}
}

FileSymlink::FileSymlink(FileSymlink&& other)
{
	m_created_junction = other.m_created_junction;
	m_hlink = other.m_hlink;
	m_junctiondir = other.m_junctiondir;
	m_linkname = other.m_linkname;
	m_target = other.m_target;

	other.m_created_junction = false;
	other.m_hlink = nullptr;
}

FileSymlink& FileSymlink::operator=(FileSymlink&& other)
{
	m_created_junction = other.m_created_junction;
	m_hlink = other.m_hlink;
	m_junctiondir = other.m_junctiondir;
	m_linkname = other.m_linkname;
	m_target = other.m_target;

	other.m_created_junction = false;
	other.m_hlink = nullptr;

	return *this;
}

static void RemovePermanentSymlink(LPCWSTR symlink, LPCWSTR target)
{
	DefineDosDeviceW(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION |
		DDD_EXACT_MATCH_ON_REMOVE, symlink, target);
	DefineDosDeviceW(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION |
		DDD_EXACT_MATCH_ON_REMOVE, symlink, target);
}

static bool CreatePermanentSymlink(LPCWSTR symlink, LPCWSTR target)
{
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, symlink, target) 
		&& DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, symlink, target))
	{
		return true;
	}
	return false;
}

bool FileSymlink::CreateSymlink(LPCWSTR xsymlink, LPCWSTR xtarget, LPCWSTR xbaseobjdir)
{
	bstr_t symlink = xsymlink;	
	bstr_t baseobjdir = L"\\RPC Control";

	if (xbaseobjdir)
	{
		baseobjdir = xbaseobjdir;
	}

	BOOL isnative;	

	bstr_t linkname = GetNativePath(symlink, &isnative);
	if (linkname.length() == 0)
	{
		return 1;
	}

	if (!isnative)
	{
		wchar_t* slash = wcsrchr(symlink.GetBSTR(), L'\\');
		if (slash == nullptr)
		{
			DebugPrintf("Error must supply a directory and link name\n");
			return false;
		}

		linkname = baseobjdir + slash;

		*slash = 0;

		m_junctiondir = symlink;

		if (!CreateDirectory(m_junctiondir, nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
		{
			DebugPrintf("Couldn't create symlink directory\n");
			return false;
		}
		
		bstr_t destdir = baseobjdir;

		if (!ReparsePoint::CreateMountPoint(m_junctiondir.GetBSTR(), destdir.GetBSTR(), L""))
		{
			DebugPrintf("Error creating junction %d\n", ReparsePoint::GetLastError());
			return false;
		}		

		m_created_junction = true;
	}

	bstr_t target = GetNativePath(xtarget, &isnative);
	if (target.length() == 0)
	{
		return false;
	}

	if (!isnative)
	{
		target = L"\\??\\" + target;
	}

	if (m_permanent)
	{
		linkname = L"Global\\GLOBALROOT" + linkname;

		if (!CreatePermanentSymlink(linkname, target))
		{
			DebugPrintf("Error creating symlink %ls\n", GetErrorMessage().c_str());
			return false;
		}
	}
	else
	{
		m_hlink = ::CreateSymlink(nullptr, linkname, target);
		if (!m_hlink)
		{
			return false;
		}		
	}

	m_linkname = linkname;
	m_target = target;

	return true;
}


bool FileSymlink::ChangeSymlink(LPCWSTR newtarget)
{
	BOOL isnative;

	bstr_t target = GetNativePath(newtarget, &isnative);
	if (target.length() == 0)
	{
		return false;
	}

	if (!isnative)
	{
		target = L"\\??\\" + target;
	}

	if (m_permanent)
	{
		RemovePermanentSymlink(m_linkname, m_target);
		if (!CreatePermanentSymlink(m_linkname, target))
		{
			return false;
		}		
	}
	else
	{
		if (!m_hlink)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			return false;
		}

		CloseHandle(m_hlink);
		m_hlink = nullptr;


		m_hlink = ::CreateSymlink(nullptr, m_linkname, target);
		if (!m_hlink)
		{
			return false;
		}
	}

	m_target = target;

	return true;
}