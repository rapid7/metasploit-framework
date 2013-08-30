// templatePropPage.cpp : Implementation of the CtemplatePropPage property page class.

#include "stdafx.h"
#include "template.h"
#include "templatePropPage.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

IMPLEMENT_DYNCREATE(CtemplatePropPage, COlePropertyPage)

// Message map

BEGIN_MESSAGE_MAP(CtemplatePropPage, COlePropertyPage)
END_MESSAGE_MAP()

// Initialize class factory and guid

IMPLEMENT_OLECREATE_EX(CtemplatePropPage, "TEMPLATE.templatePropPage.1",
	0xe4f15977, 0x89d6, 0x46fa, 0x8b, 0x37, 0x5e, 0xbd, 0x8b, 0x36, 0xb5, 0x1)

// CtemplatePropPage::CtemplatePropPageFactory::UpdateRegistry -
// Adds or removes system registry entries for CtemplatePropPage

BOOL CtemplatePropPage::CtemplatePropPageFactory::UpdateRegistry(BOOL bRegister)
{
	if (bRegister)
		return AfxOleRegisterPropertyPageClass(AfxGetInstanceHandle(),
			m_clsid, IDS_TEMPLATE_PPG);
	else
		return AfxOleUnregisterClass(m_clsid, NULL);
}

// CtemplatePropPage::CtemplatePropPage - Constructor

CtemplatePropPage::CtemplatePropPage() :
	COlePropertyPage(0, IDS_TEMPLATE_PPG_CAPTION)
{
}

// CtemplatePropPage::DoDataExchange - Moves data between page and properties

void CtemplatePropPage::DoDataExchange(CDataExchange* pDX)
{
	DDP_PostProcessing(pDX);
}

// CtemplatePropPage message handlers
