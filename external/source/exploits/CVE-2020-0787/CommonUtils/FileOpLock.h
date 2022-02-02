#pragma once

#include <Windows.h>
#include <string>

class FileOpLock
{
public:
	typedef void(*UserCallback)();

	static FileOpLock* CreateLock(const std::wstring& name, const std::wstring& share_mode, FileOpLock::UserCallback cb);
	void WaitForLock(UINT Timeout);

	~FileOpLock();
private:

	HANDLE g_hFile;
	OVERLAPPED g_o;
	REQUEST_OPLOCK_INPUT_BUFFER g_inputBuffer;
	REQUEST_OPLOCK_OUTPUT_BUFFER g_outputBuffer;
	HANDLE g_hLockCompleted;
	PTP_WAIT g_wait;	
	UserCallback _cb;

	FileOpLock(UserCallback cb);

	static void CALLBACK WaitCallback(PTP_CALLBACK_INSTANCE Instance,
		PVOID Parameter, PTP_WAIT Wait,
		TP_WAIT_RESULT WaitResult);

	void DoWaitCallback();

	bool BeginLock(const std::wstring& name, DWORD dwShareMode, bool exclusive);

};

