#pragma once

// templatePropPage.h : Declaration of the CtemplatePropPage property page class.


// CtemplatePropPage : See templatePropPage.cpp for implementation.

class CtemplatePropPage : public COlePropertyPage
{
	DECLARE_DYNCREATE(CtemplatePropPage)
	DECLARE_OLECREATE_EX(CtemplatePropPage)

// Constructor
public:
	CtemplatePropPage();

// Implementation
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Message maps
protected:
	DECLARE_MESSAGE_MAP()
};

