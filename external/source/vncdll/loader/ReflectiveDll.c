//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//
#include "ReflectiveLoader.h"

#define EXITFUNC_SEH		0xEA320EFE
#define EXITFUNC_THREAD		0x0A2A1DE0
#define EXITFUNC_PROCESS	0x56A2B5F0

#define DLL_METASPLOIT_ATTACH	4
#define DLL_METASPLOIT_DETACH	5
#define DLL_QUERY_HMODULE		6

// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;
//===============================================================================================//
extern DWORD DLLEXPORT Init(SOCKET socket);

BOOL MetasploitDllAttach(SOCKET socket)
{
	Init(socket);
	return TRUE;
}

BOOL MetasploitDllDetach(DWORD dwExitFunc)
{
	switch (dwExitFunc)
	{
	case EXITFUNC_SEH:
		SetUnhandledExceptionFilter(NULL);
		break;
	case EXITFUNC_THREAD:
		ExitThread(0);
		break;
	case EXITFUNC_PROCESS:
		ExitProcess(0);
		break;
	default:
		break;
	}

	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_METASPLOIT_ATTACH:
		bReturnValue = MetasploitDllAttach((SOCKET) lpReserved);
		break;
	case DLL_METASPLOIT_DETACH:
		bReturnValue = MetasploitDllDetach((DWORD) lpReserved);
		break;
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *) lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}