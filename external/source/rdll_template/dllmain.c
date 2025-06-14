#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
#include "ReflectiveLoader.c"

#include <stdio.h>
#include <stdint.h>
#include <windows.h>

LPVOID main(LPVOID lpReserved) {
	return;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
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
		main(lpReserved);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

