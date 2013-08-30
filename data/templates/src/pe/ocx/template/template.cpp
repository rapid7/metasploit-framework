// template.cpp : Implementation of CtemplateApp and DLL registration.

#include "stdafx.h"
#include "template.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


CtemplateApp theApp;

const GUID CDECL _tlid = { 0xF8F555A6, 0xC743, 0x4334, { 0x8B, 0xE9, 0xCC, 0x4C, 0xCC, 0x57, 0xCD, 0x75 } };
const WORD _wVerMajor = 1;
const WORD _wVerMinor = 0;



// CtemplateApp::InitInstance - DLL initialization

BOOL CtemplateApp::InitInstance()
{
	BOOL bInit = COleControlModule::InitInstance();

	if (bInit)
	{
		// TODO: Add your own module initialization code here.
	}

	return bInit;
}



// CtemplateApp::ExitInstance - DLL termination

int CtemplateApp::ExitInstance()
{
	// TODO: Add your own module termination code here.

	return COleControlModule::ExitInstance();
}



// DllRegisterServer - Adds entries to the system registry

STDAPI DllRegisterServer(void)
{
	AFX_MANAGE_STATE(_afxModuleAddrThis);

	if (!AfxOleRegisterTypeLib(AfxGetInstanceHandle(), _tlid))
		return ResultFromScode(SELFREG_E_TYPELIB);

	if (!COleObjectFactoryEx::UpdateRegistryAll(TRUE))
		return ResultFromScode(SELFREG_E_CLASS);

	return NOERROR;
}



// DllUnregisterServer - Removes entries from the system registry

STDAPI DllUnregisterServer(void)
{
	AFX_MANAGE_STATE(_afxModuleAddrThis);

	if (!AfxOleUnregisterTypeLib(_tlid, _wVerMajor, _wVerMinor))
		return ResultFromScode(SELFREG_E_TYPELIB);

	if (!COleObjectFactoryEx::UpdateRegistryAll(FALSE))
		return ResultFromScode(SELFREG_E_CLASS);

	return NOERROR;
}
