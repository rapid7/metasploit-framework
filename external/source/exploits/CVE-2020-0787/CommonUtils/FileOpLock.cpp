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
#include "FileOpLock.h"
#include <threadpoolapiset.h>

void DebugPrintf(LPCSTR lpFormat, ...);

FileOpLock::FileOpLock(UserCallback cb):
	g_inputBuffer({ 0 }), g_outputBuffer({ 0 }), g_o({ 0 }), g_hFile(INVALID_HANDLE_VALUE), g_hLockCompleted(nullptr), g_wait(nullptr), _cb(cb)
{
	g_inputBuffer.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	g_inputBuffer.StructureLength = sizeof(g_inputBuffer);
	g_inputBuffer.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
	g_inputBuffer.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;	
	g_outputBuffer.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	g_outputBuffer.StructureLength = sizeof(g_outputBuffer);
}


FileOpLock::~FileOpLock()
{
	if (g_wait)
	{
		SetThreadpoolWait(g_wait, nullptr, nullptr);
		CloseThreadpoolWait(g_wait);
		g_wait = nullptr;
	}

	if (g_o.hEvent)
	{
		CloseHandle(g_o.hEvent);
		g_o.hEvent = nullptr;
	}

	if (g_hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(g_hFile);
		g_hFile = INVALID_HANDLE_VALUE;
	}
}

bool FileOpLock::BeginLock(const std::wstring& filename, DWORD dwShareMode, bool exclusive)
{
	g_hLockCompleted = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_o.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

	DWORD flags = FILE_FLAG_OVERLAPPED;

	if (GetFileAttributesW(filename.c_str()) & FILE_ATTRIBUTE_DIRECTORY)
	{
		flags |= FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
	}

	g_hFile = CreateFileW(filename.c_str(), GENERIC_READ,
		dwShareMode, nullptr, OPEN_EXISTING,
		flags, nullptr);
	if (g_hFile == INVALID_HANDLE_VALUE) {
		DebugPrintf("Error opening file: %d\n", GetLastError());
		return false;
	}

	g_wait = CreateThreadpoolWait(WaitCallback, this, nullptr);
	if (g_wait == nullptr)
	{
		DebugPrintf("Error creating threadpool %d\n", GetLastError());
		return false;
	}

	SetThreadpoolWait(g_wait, g_o.hEvent, nullptr);

	DWORD bytesReturned;

  if (exclusive)
  {
    DeviceIoControl(g_hFile,
      FSCTL_REQUEST_OPLOCK_LEVEL_1,
      NULL, 0,
      NULL, 0,
      &bytesReturned,
      &g_o);
  }
  else
  {
    DeviceIoControl(g_hFile, FSCTL_REQUEST_OPLOCK,
      &g_inputBuffer, sizeof(g_inputBuffer),
      &g_outputBuffer, sizeof(g_outputBuffer),
      nullptr, &g_o);
  }

	DWORD err = GetLastError();
	if (err != ERROR_IO_PENDING) {
		DebugPrintf("Oplock Failed %d\n", err);
		return false;
	}
	
	return true;
}

FileOpLock* FileOpLock::CreateLock(const std::wstring& name, const std::wstring& share_mode, FileOpLock::UserCallback cb)
{
	FileOpLock* ret = new FileOpLock(cb);
	DWORD dwShareMode = 0;
  bool exclusive = false;

	if (share_mode.find('r') != std::wstring::npos)
	{
		dwShareMode |= FILE_SHARE_READ;
	}

	if (share_mode.find('w') != std::wstring::npos)
	{
		dwShareMode |= FILE_SHARE_WRITE;
	}

	if (share_mode.find('d') != std::wstring::npos)
	{
		dwShareMode |= FILE_SHARE_DELETE;
	}

  if (share_mode.find('x') != std::wstring::npos)
  {
    exclusive = true;
  }

	if (ret->BeginLock(name, dwShareMode, exclusive))
	{
		return ret;
	}
	else
	{
		delete ret;
		return nullptr;
	}
}

void FileOpLock::WaitForLock(UINT Timeout)
{	
	WaitForSingleObject(g_hLockCompleted, Timeout);
}

void FileOpLock::WaitCallback(PTP_CALLBACK_INSTANCE Instance,
	PVOID Parameter, PTP_WAIT Wait,
	TP_WAIT_RESULT WaitResult)
{
	UNREFERENCED_PARAMETER(Instance);
	UNREFERENCED_PARAMETER(Wait);
	UNREFERENCED_PARAMETER(WaitResult);

	FileOpLock* lock = reinterpret_cast<FileOpLock*>(Parameter);

	lock->DoWaitCallback();	
}

void FileOpLock::DoWaitCallback()
{	
	DWORD dwBytes;
	if (!GetOverlappedResult(g_hFile, &g_o, &dwBytes, TRUE)) {
		DebugPrintf("Oplock Failed\n");		
	}
	
	if (_cb)
	{
		_cb();
	}
	
	//DebugPrintf("Closing Handle\n");
	CloseHandle(g_hFile);
	g_hFile = INVALID_HANDLE_VALUE;
	SetEvent(g_hLockCompleted);
}