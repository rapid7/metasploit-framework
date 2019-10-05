// Author: B4rtik (@b4rtik)
// Project: Execute-dotnet-assembly (https://github.com/b4rtik/metasploit-execute-assembly)
// License: BSD 3-Clause

#include "stdafx.h"
#include "ReflectiveLoader.h"
#include "HostingCLR.h"

extern HINSTANCE hAppInstance;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		Execute(lpReserved);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
