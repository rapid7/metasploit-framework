#include "stdafx.h"
#include "FileOpLock.h"
#include <threadpoolapiset.h>



FileOpLock::FileOpLock(UserCallback cb) :
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
bool FileOpLock::BeginLock(const std::wstring& filename)
{
	g_hLockCompleted = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_o.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);



	g_hFile = CreateFileW(filename.c_str(), GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
		0, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_BACKUP_SEMANTICS, 0);
	if (g_hFile == INVALID_HANDLE_VALUE) {

		return false;
	}

	g_wait = CreateThreadpoolWait(WaitCallback, this, nullptr);
	if (g_wait == nullptr)
	{

		return false;
	}

	SetThreadpoolWait(g_wait, g_o.hEvent, nullptr);

	DeviceIoControl(g_hFile, FSCTL_REQUEST_OPLOCK,
		&g_inputBuffer, sizeof(g_inputBuffer),
		&g_outputBuffer, sizeof(g_outputBuffer),
		nullptr, &g_o);
	if (GetLastError() != ERROR_IO_PENDING) {

		return false;
	}

	return true;
}
bool FileOpLock::BeginLock(HANDLE hfile)
{
	g_hLockCompleted = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_o.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);



	g_hFile = hfile;
	if (g_hFile == INVALID_HANDLE_VALUE) {

		return false;
	}

	g_wait = CreateThreadpoolWait(WaitCallback, this, nullptr);
	if (g_wait == nullptr)
	{

		return false;
	}

	SetThreadpoolWait(g_wait, g_o.hEvent, nullptr);

	DeviceIoControl(g_hFile, FSCTL_REQUEST_OPLOCK,
		&g_inputBuffer, sizeof(g_inputBuffer),
		&g_outputBuffer, sizeof(g_outputBuffer),
		nullptr, &g_o);
	if (GetLastError() != ERROR_IO_PENDING) {

		return false;
	}

	return true;
}
FileOpLock* FileOpLock::CreateLock(const std::wstring& name, FileOpLock::UserCallback cb)
{
	FileOpLock* ret = new FileOpLock(cb);

	if (ret->BeginLock(name))
	{
		return ret;
	}
	else
	{
		delete ret;
		return nullptr;
	}
}
FileOpLock* FileOpLock::CreateLock(HANDLE hfile, FileOpLock::UserCallback cb)
{
	FileOpLock* ret = new FileOpLock(cb);

	if (ret->BeginLock(hfile))
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
void FileOpLock::WaitCallback2(PTP_CALLBACK_INSTANCE Instance,
	PVOID Parameter, PTP_WAIT Wait,
	TP_WAIT_RESULT WaitResult)
{
	UNREFERENCED_PARAMETER(Instance);
	UNREFERENCED_PARAMETER(Wait);
	UNREFERENCED_PARAMETER(WaitResult);

	FileOpLock* lock = reinterpret_cast<FileOpLock*>(Parameter);

	lock->DoWaitCallbackt();
}
void FileOpLock::DoWaitCallbackt()
{
	DWORD dwBytes;
	if (!GetOverlappedResult(g_hFile, &g_o, &dwBytes, TRUE)) {

	}

	if (_cb)
	{
		_cb();
	}
	g_hFile = INVALID_HANDLE_VALUE;
	SetEvent(g_hLockCompleted);
}
void FileOpLock::DoWaitCallback()
{
	DWORD dwBytes;
	if (!GetOverlappedResult(g_hFile, &g_o, &dwBytes, TRUE)) {

	}

	if (_cb)
	{
		_cb();
	}


	CloseHandle(g_hFile);
	g_hFile = INVALID_HANDLE_VALUE;
	SetEvent(g_hLockCompleted);
}

