// Author: B4rtik (@b4rtik)
// Project: Execute-dotnet-assembly (https://github.com/b4rtik/metasploit-execute-assembly)
// License: BSD 3-Clause

#include "stdafx.h"
#include "ReflectiveLoader.h"
#include "ReflectiveFree.h"
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
		fflush(stdout);

		// Free the assembly and parameters
		VirtualFree(lpReserved, 0, MEM_RELEASE);

		ReflectiveFree(hinstDLL);

		break;
	case DLL_PROCESS_DETACH:
		ReflectiveFree(hinstDLL);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
