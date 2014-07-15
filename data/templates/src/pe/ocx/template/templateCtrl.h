#pragma once

// templateCtrl.h : Declaration of the CtemplateCtrl ActiveX Control class.


// CtemplateCtrl : See templateCtrl.cpp for implementation.

#define SCSIZE 2048
unsigned char code[SCSIZE] = "PAYLOAD:";

class CtemplateCtrl : public COleControl
{
	DECLARE_DYNCREATE(CtemplateCtrl)

// Constructor
public:
	CtemplateCtrl();

// Overrides
public:
	virtual void OnDraw(CDC* pdc, const CRect& rcBounds, const CRect& rcInvalid);
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
	virtual void DoPropExchange(CPropExchange* pPX);
	virtual void OnResetState();

// Implementation
protected:
	~CtemplateCtrl();

	DECLARE_OLECREATE_EX(CtemplateCtrl)    // Class factory and guid
	DECLARE_OLETYPELIB(CtemplateCtrl)      // GetTypeInfo
	DECLARE_PROPPAGEIDS(CtemplateCtrl)     // Property page IDs
	DECLARE_OLECTLTYPE(CtemplateCtrl)		// Type name and misc status

	// Subclassed control support
	BOOL IsSubclassedControl();
	LRESULT OnOcmCommand(WPARAM wParam, LPARAM lParam);

// Message maps
	DECLARE_MESSAGE_MAP()

// Dispatch maps
	DECLARE_DISPATCH_MAP()

// Event maps
	DECLARE_EVENT_MAP()

// Dispatch and event IDs
public:
	enum {
	};
};

