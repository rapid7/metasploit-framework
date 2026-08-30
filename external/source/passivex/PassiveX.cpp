#include "PassiveXLib.h"

#include <objbase.h>
#include <initguid.h>

#include "PassiveX_i.c"
#include "CPassiveX.h"

CComModule _Module;

BEGIN_OBJECT_MAP(ObjectMap)
	OBJECT_ENTRY(CLSID_PassiveX, CPassiveX)
END_OBJECT_MAP()

namespace ATL
{
    void * __stdcall __AllocStdCallThunk()
    {
        return HeapAlloc( GetProcessHeap(), 0, sizeof(_stdcallthunk) );
    }

    void __stdcall __FreeStdCallThunk( void * p )
    {
        HeapFree( GetProcessHeap(), 0, p );
    }
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		_Module.Init(ObjectMap, hInstance, &LIBID_PassiveXCOM);
		DisableThreadLibraryCalls(hInstance);
	}
	else if (dwReason == DLL_PROCESS_DETACH)
		_Module.Term();

	return TRUE;  
}

STDAPI DllCanUnloadNow(void)
{
	return (_Module.GetLockCount()==0) ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
	return _Module.GetClassObject(rclsid, riid, ppv);
}

STDAPI DllRegisterServer(void)
{
	return _Module.RegisterServer(TRUE);
}

STDAPI DllUnregisterServer(void)
{
	return _Module.UnregisterServer(TRUE);
}
