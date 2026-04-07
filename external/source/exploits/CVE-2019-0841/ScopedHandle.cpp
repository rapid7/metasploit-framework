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
#include "ScopedHandle.h"

static HANDLE Duplicate(HANDLE h)
{
	HANDLE dup;

	if ((h == INVALID_HANDLE_VALUE) || !DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
	{
		return nullptr;
	}
	else
	{
		return dup;
	}
}

ScopedHandle::ScopedHandle(HANDLE h, bool duplicate)
{	
	if (duplicate)
	{
		g_h = Duplicate(h);
	}
	else
	{
		g_h = h;
	}
}

ScopedHandle::ScopedHandle(const ScopedHandle& other)
{
	g_h = Duplicate(other.g_h);
}

ScopedHandle& ScopedHandle::operator=(const ScopedHandle& other)
{
	if (this != &other)
	{
		g_h = Duplicate(other.g_h);
	}

	return *this;
}

ScopedHandle::ScopedHandle(ScopedHandle&& other)
{
	g_h = other.g_h;
	other.g_h = nullptr;
}

ScopedHandle& ScopedHandle::operator=(ScopedHandle&& other)
{
	if (this != &other)
	{
		g_h = other.g_h;
		other.g_h = nullptr;
	}

	return *this;
}

void ScopedHandle::Close() 
{
	if (IsValid())
	{
		CloseHandle(g_h);
		g_h = nullptr;
	}
}

void ScopedHandle::Reset(HANDLE h)
{
	Close();
	g_h = h;
}

ScopedHandle::~ScopedHandle()
{
	Close();
}
