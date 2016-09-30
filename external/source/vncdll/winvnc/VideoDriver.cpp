//  Copyright (C) 2005-2006 Lev Kazarkin. All Rights Reserved.
//
//  TightVNC is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
//  USA.
//
// TightVNC distribution homepage on the Web: http://www.tightvnc.com/

#include "VideoDriver.h"
#include "vncDesktop.h"

char	vncVideoDriver::szDriverString[] = "Mirage Driver";
char	vncVideoDriver::szDriverStringAlt[] = "DemoForge Mirage Driver";
char	vncVideoDriver::szMiniportName[] = "dfmirage";

#define MINIPORT_REGISTRY_PATH	"SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current\\System\\CurrentControlSet\\Services"

BOOL IsWinNT();
BOOL IsNtVer(ULONG mj, ULONG mn);
BOOL IsWinVerOrHigher(ULONG mj, ULONG mn);


vncVideoDriver::vncVideoDriver()
{
	bufdata.buffer = NULL;
	bufdata.Userbuffer = NULL;
	m_fIsActive = false;
	m_fDirectAccessInEffect = false;
	m_fHandleScreen2ScreenBlt = false;
	*m_devname= 0;
	m_drv_ver_mj = 0;
	m_drv_ver_mn = 0;
}

vncVideoDriver::~vncVideoDriver()
{
	UnMapSharedbuffers();
	Deactivate();
	_ASSERTE(!m_fIsActive);
	_ASSERTE(!m_fDirectAccessInEffect);
}

#define	BYTE0(x)	((x) & 0xFF)
#define	BYTE1(x)	(((x) >> 8) & 0xFF)
#define	BYTE2(x)	(((x) >> 16) & 0xFF)
#define	BYTE3(x)	(((x) >> 24) & 0xFF)

BOOL vncVideoDriver::CheckVersion()
{
	_ASSERTE(IsWinNT());

	HDC	l_gdc= ::CreateDC(m_devname, NULL, NULL, NULL);
	if (!l_gdc)
	{
		return FALSE;
	}

	Esc_dmf_Qvi_IN qvi_in;
	qvi_in.cbSize = sizeof(qvi_in);

	qvi_in.app_actual_version = DMF_PROTO_VER_CURRENT;
	qvi_in.display_minreq_version = DMF_PROTO_VER_MINCOMPAT;
	qvi_in.connect_options = 0;

	Esc_dmf_Qvi_OUT qvi_out;
	qvi_out.cbSize = sizeof(qvi_out);

	int drvCr = ExtEscape(
		l_gdc,
		ESC_QVI,
		sizeof(qvi_in), (LPSTR) &qvi_in,
		sizeof(qvi_out), (LPSTR) &qvi_out);
	DeleteDC(l_gdc);

	if (drvCr == 0)
	{
		return FALSE;
	}

	if (drvCr < 0)
	{
		return FALSE;
	}

	m_drv_ver_mj = BYTE3(qvi_out.display_actual_version);
	m_drv_ver_mn = BYTE2(qvi_out.display_actual_version);

	return TRUE;
}

BOOL vncVideoDriver::MapSharedbuffers(BOOL fForDirectScreenAccess)
{
	_ASSERTE(!m_fIsActive);
	_ASSERTE(!m_fDirectAccessInEffect);
	_ASSERTE(IsWinNT());

	HDC	l_gdc= ::CreateDC(m_devname, NULL, NULL, NULL);
	if (!l_gdc)
	{
		return FALSE;
	}

	oldCounter = 0;
	int drvCr = ExtEscape(
		l_gdc,
		MAP1,
		0, NULL,
		sizeof(GETCHANGESBUF), (LPSTR) &bufdata);
	DeleteDC(l_gdc);

	if (drvCr <= 0)
	{
		return FALSE;
	}
	m_fIsActive = true;
	if (fForDirectScreenAccess)
	{
		if (!bufdata.Userbuffer)
		{
			return FALSE;
		}
		m_fDirectAccessInEffect = true;
	}

// Screen2Screen support added in Mirage ver 1.2
	m_fHandleScreen2ScreenBlt = (m_drv_ver_mj > 1) || (m_drv_ver_mj == 1 && m_drv_ver_mn >= 2);

	return TRUE;	
}

BOOL vncVideoDriver::TestMapped()
{
	_ASSERTE(IsWinNT());

	TCHAR *pDevName;
	if (IsWinVerOrHigher(5, 0))
	{
		DISPLAY_DEVICE dd;
		INT devNum = 0;
		if (!LookupVideoDeviceAlt(szDriverString, szDriverStringAlt, devNum, &dd))
			return FALSE;
		pDevName = (TCHAR *)dd.DeviceName;
	}
	else
	{
		pDevName = "DISPLAY";
	}

	HDC	l_ddc = ::CreateDC(pDevName, NULL, NULL, NULL);
	if (l_ddc)
	{
		BOOL b = ExtEscape(l_ddc, TESTMAPPED, 0, NULL, 0, NULL);	
		DeleteDC(l_ddc);
		return b;
	}
	return FALSE;
}

void vncVideoDriver::UnMapSharedbuffers()
{
	_ASSERTE(IsWinNT());

	int DrvCr = 0;
	if (m_devname[0])
	{
		_ASSERTE(m_fIsActive);
		_ASSERTE(bufdata.buffer);
		_ASSERTE(!m_fDirectAccessInEffect || bufdata.Userbuffer);

		HDC	l_gdc= ::CreateDC(m_devname, NULL, NULL, NULL);
		if (l_gdc)
		{
			DrvCr = ExtEscape(
				l_gdc,
				UNMAP1,
				sizeof(GETCHANGESBUF), (LPSTR) &bufdata,
				0, NULL);
			DeleteDC(l_gdc);

			_ASSERTE(DrvCr > 0);
		}
	}
// 0 return value is unlikely for Mirage because its DC is independent
// from the reference device;
// this happens with Quasar if its mode was changed externally.
// nothing is particularly bad with it.

	if (DrvCr <= 0)
	{
		if (bufdata.buffer)
		{
			BOOL br = UnmapViewOfFile(bufdata.buffer);
		}
		if (bufdata.Userbuffer)
		{
			BOOL br = UnmapViewOfFile(bufdata.Userbuffer);
		}
	}
	m_fIsActive = false;
	m_fDirectAccessInEffect = false;
	m_fHandleScreen2ScreenBlt = false;
}

template <class TpFn>
HINSTANCE  LoadNImport(LPCTSTR szDllName, LPCTSTR szFName, TpFn &pfn)
{
	HINSTANCE hDll = LoadLibrary(szDllName);
	if (hDll)
	{
		pfn = (TpFn)GetProcAddress(hDll, szFName);
		if (pfn)
			return hDll;
		FreeLibrary(hDll);
	}
	return NULL;
}

//BOOL vncVideoDriver::LookupVideoDevice(LPCTSTR szDeviceString, INT &devNum, DISPLAY_DEVICE *pDd)
BOOL vncVideoDriver::LookupVideoDeviceAlt(
		LPCTSTR szDevStr,
		LPCTSTR szDevStrAlt,
		INT &devNum,
		DISPLAY_DEVICE *pDd)
{
	_ASSERTE(IsWinVerOrHigher(5, 0));

	pEnumDisplayDevices pd = NULL;
	HINSTANCE  hInstUser32 = LoadNImport("User32.DLL", "EnumDisplayDevicesA", pd);
	if (!hInstUser32) return FALSE;

	ZeroMemory(pDd, sizeof(DISPLAY_DEVICE));
	pDd->cb = sizeof(DISPLAY_DEVICE);
	BOOL result;
	while (result = (*pd)(NULL,devNum, pDd, 0))
	{
		if (strcmp((const char *)pDd->DeviceString, szDevStr) == 0 ||
			szDevStrAlt && strcmp((const char *)pDd->DeviceString, szDevStrAlt) == 0)
		{
			break;
		}
		devNum++;
	}

	FreeLibrary(hInstUser32);
	return result;
}

HKEY vncVideoDriver::CreateDeviceKey(LPCTSTR szMpName)
{
	HKEY hKeyProfileMirror = (HKEY)0;
	if (RegCreateKey(
			HKEY_LOCAL_MACHINE,
			(MINIPORT_REGISTRY_PATH),
			&hKeyProfileMirror) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	HKEY hKeyProfileMp = (HKEY)0;
	LONG cr = RegCreateKey(
			hKeyProfileMirror,
			szMpName,
			&hKeyProfileMp);
	RegCloseKey(hKeyProfileMirror);
	if (cr != ERROR_SUCCESS)
	{
		return FALSE;
	}
	HKEY hKeyDevice = (HKEY)0;
	if (RegCreateKey(
			hKeyProfileMp,
			("DEVICE0"),
			&hKeyDevice) != ERROR_SUCCESS)
	{

	}
	RegCloseKey(hKeyProfileMp);
	return hKeyDevice;
}

BOOL vncVideoDriver::Activate(
		BOOL fForDirectAccess,
		const RECT *prcltarget)
{
	_ASSERTE(IsWinNT());

	if (IsWinVerOrHigher(5, 0))
	{
		return Activate_NT50(fForDirectAccess, prcltarget);
	}
	else
	{
// NOTE: prcltarget is just a SourceDisplayRect.
// there is only 1 possibility on NT4, so safely ignore it
		return Activate_NT46(fForDirectAccess);
	}
}

void vncVideoDriver::Deactivate()
{
	_ASSERTE(IsWinNT());

	if (IsWinVerOrHigher(5, 0))
	{
		Deactivate_NT50();
	}
	else
	{
		Deactivate_NT46();
	}
}

BOOL vncVideoDriver::Activate_NT50(
		BOOL fForDirectAccess,
		const RECT *prcltarget)
{
	HDESK   hdeskInput;
    HDESK   hdeskCurrent;
 
	DISPLAY_DEVICE dd;
	INT devNum = 0;
	if (!LookupVideoDeviceAlt(szDriverString, szDriverStringAlt, devNum, &dd))
	{
		return FALSE;
	}

	DEVMODE devmode;
	FillMemory(&devmode, sizeof(DEVMODE), 0);
	devmode.dmSize = sizeof(DEVMODE);
	devmode.dmDriverExtra = 0;
	BOOL change = EnumDisplaySettings(NULL, ENUM_CURRENT_SETTINGS, &devmode);
	devmode.dmFields = DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT;
	if (prcltarget)
	{
// we always have to set position or
// a stale position info in registry would come into effect.
		devmode.dmFields |= DM_POSITION;
		devmode.dmPosition.x = prcltarget->left;
		devmode.dmPosition.y = prcltarget->top;

		devmode.dmPelsWidth = prcltarget->right - prcltarget->left;
		devmode.dmPelsHeight = prcltarget->bottom - prcltarget->top;
	}

	devmode.dmDeviceName[0] = '\0';

	HKEY hKeyDevice = CreateDeviceKey(szMiniportName);
	if (hKeyDevice == NULL)
		return FALSE;

// TightVNC does not use these features
	RegDeleteValue(hKeyDevice, ("Screen.ForcedBpp"));
	RegDeleteValue(hKeyDevice, ("Pointer.Enabled"));

	DWORD dwVal = fForDirectAccess ? 3 : 0;
// NOTE that old driver ignores it and mapping is always ON with it
	if (RegSetValueEx(
			hKeyDevice,
			("Cap.DfbBackingMode"),
			0,
			REG_DWORD,
			(unsigned char *)&dwVal,
			4) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	dwVal = 1;
	if (RegSetValueEx(
		hKeyDevice,
		("Order.BltCopyBits.Enabled"),
		0,
		REG_DWORD,
		(unsigned char *)&dwVal,
		4) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	dwVal = 1;
	if (RegSetValueEx(
			hKeyDevice,
			("Attach.ToDesktop"),
			0,
			REG_DWORD,
			(unsigned char *)&dwVal,
			4) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	pChangeDisplaySettingsEx pCDS = NULL;
	HINSTANCE  hInstUser32 = LoadNImport("User32.DLL", "ChangeDisplaySettingsExA", pCDS);
	if (!hInstUser32) return FALSE;

	// Save the current desktop
	hdeskCurrent = GetThreadDesktop(GetCurrentThreadId());
	if (hdeskCurrent != NULL)
	{
		hdeskInput = OpenInputDesktop(0, FALSE, MAXIMUM_ALLOWED);
		if (hdeskInput != NULL) 
			SetThreadDesktop(hdeskInput);
	}
// 24 bpp screen mode is MUNGED to 32 bpp.
// the underlying buffer format must be 32 bpp.
// see vncDesktop::ThunkBitmapInfo()
	if (devmode.dmBitsPerPel==24) devmode.dmBitsPerPel = 32;
	LONG cr = (*pCDS)(
		(TCHAR *)dd.DeviceName,
		&devmode,
		NULL,
		CDS_UPDATEREGISTRY,NULL);

	strcpy(m_devname, (const char *)dd.DeviceName);

	// Reset desktop
	SetThreadDesktop(hdeskCurrent);
	// Close the input desktop
	CloseDesktop(hdeskInput);
	RegCloseKey(hKeyDevice);
	FreeLibrary(hInstUser32);

	return TRUE;
}

BOOL vncVideoDriver::Activate_NT46(BOOL fForDirectAccess)
{
	HKEY hKeyDevice = CreateDeviceKey(szMiniportName);
	if (hKeyDevice == NULL)
		return FALSE;

	// TightVNC does not use these features
	RegDeleteValue(hKeyDevice, ("Screen.ForcedBpp"));
	RegDeleteValue(hKeyDevice, ("Pointer.Enabled"));

	DWORD dwVal = fForDirectAccess ? 3 : 0;
	// NOTE that old driver ignores it and mapping is always ON with it
	if (RegSetValueEx(
		hKeyDevice,
		("Cap.DfbBackingMode"),
		0,
		REG_DWORD,
		(unsigned char *)&dwVal,
		4) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	dwVal = 1;
	if (RegSetValueEx(
		hKeyDevice,
		("Order.BltCopyBits.Enabled"),
		0,
		REG_DWORD,
		(unsigned char *)&dwVal,
		4) != ERROR_SUCCESS)
	{
		return FALSE;
	}

// NOTE: we cannot truly load the driver
// but ChangeDisplaySettings makes PDEV to reload
// and thus new settings come into effect

// TODO

	strcpy(m_devname, "DISPLAY");

	RegCloseKey(hKeyDevice);
	return TRUE;
}

void vncVideoDriver::Deactivate_NT50()
{
	HDESK   hdeskInput;
	HDESK   hdeskCurrent;
 
// it is important to us to be able to deactivate
// even what we have never activated. thats why we look it up, all over
//	if (!m_devname[0])
//		return;
// ... and forget the name
	*m_devname = 0;

	DISPLAY_DEVICE dd;
	INT devNum = 0;
	if (!LookupVideoDeviceAlt(szDriverString, szDriverStringAlt, devNum, &dd))
	{
		return;
	}

	DEVMODE devmode;
	FillMemory(&devmode, sizeof(DEVMODE), 0);
	devmode.dmSize = sizeof(DEVMODE);
	devmode.dmDriverExtra = 0;
	BOOL change = EnumDisplaySettings(NULL, ENUM_CURRENT_SETTINGS, &devmode);
	devmode.dmFields = DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT;
	devmode.dmDeviceName[0] = '\0';

	HKEY hKeyDevice = CreateDeviceKey(szMiniportName);
	if (hKeyDevice == NULL)
		return;

    DWORD one = 0;
	if (RegSetValueEx(hKeyDevice,("Attach.ToDesktop"), 0, REG_DWORD, (unsigned char *)&one,4) != ERROR_SUCCESS)
	{

	}

// reverting to default behavior
	RegDeleteValue(hKeyDevice, ("Cap.DfbBackingMode"));
	RegDeleteValue(hKeyDevice, ("Order.BltCopyBits.Enabled"));

	pChangeDisplaySettingsEx pCDS = NULL;
	HINSTANCE  hInstUser32 = LoadNImport("User32.DLL", "ChangeDisplaySettingsExA", pCDS);
	if (!hInstUser32) return;

	// Save the current desktop
	hdeskCurrent = GetThreadDesktop(GetCurrentThreadId());
	if (hdeskCurrent != NULL)
	{
		hdeskInput = OpenInputDesktop(0, FALSE, MAXIMUM_ALLOWED);
		if (hdeskInput != NULL)
			SetThreadDesktop(hdeskInput);
	}
// 24 bpp screen mode is MUNGED to 32 bpp. see vncDesktop::ThunkBitmapInfo()
	if (devmode.dmBitsPerPel==24) devmode.dmBitsPerPel = 32;

	// Add 'Default.*' settings to the registry under above hKeyProfile\mirror\device
	(*pCDS)((TCHAR *)dd.DeviceName, &devmode, NULL, CDS_UPDATEREGISTRY, NULL);

	// Reset desktop
	SetThreadDesktop(hdeskCurrent);
	// Close the input desktop
	CloseDesktop(hdeskInput);
	RegCloseKey(hKeyDevice);
	FreeLibrary(hInstUser32);
}

void vncVideoDriver::Deactivate_NT46()
{
// ... and forget the name
	*m_devname = 0;

	HKEY hKeyDevice = CreateDeviceKey(szMiniportName);
	if (hKeyDevice == NULL)
		return;

// reverting to default behavior
	RegDeleteValue(hKeyDevice, ("Cap.DfbBackingMode"));

//	RegDeleteValue(hKeyDevice, ("Order.BltCopyBits.Enabled"));
// TODO: remove "Order.BltCopyBits.Enabled"
// now we don't touch this important option
// because we dont apply the changed values

	RegCloseKey(hKeyDevice);
}

void vncVideoDriver::HandleDriverChanges(
		vncDesktop *pDesk,
		vncRegion &rgn,
		int xoffset,
		int yoffset,
		BOOL &bPointerShapeChange)
{
	ULONG snapshot_counter = bufdata.buffer->counter;
	if (oldCounter == snapshot_counter)
		return;

	if (oldCounter < snapshot_counter)
	{
		HandleDriverChangesSeries(
			pDesk,
			rgn,
			xoffset, yoffset,
			bufdata.buffer->pointrect + oldCounter,
			bufdata.buffer->pointrect + snapshot_counter,
			bPointerShapeChange);
	}
	else
	{
		HandleDriverChangesSeries(
			pDesk,
			rgn,
			xoffset, yoffset,
			bufdata.buffer->pointrect + oldCounter,
			bufdata.buffer->pointrect + MAXCHANGES_BUF,
			bPointerShapeChange);

		HandleDriverChangesSeries(
			pDesk,
			rgn,
			xoffset, yoffset,
			bufdata.buffer->pointrect,
			bufdata.buffer->pointrect + snapshot_counter,
			bPointerShapeChange);
	}

	oldCounter = snapshot_counter;
}

void vncVideoDriver::HandleDriverChangesSeries(
		vncDesktop *pDesk,
		vncRegion &rgn,
		int xoffset,
		int yoffset,
		const CHANGES_RECORD *i,
		const CHANGES_RECORD *last,
		BOOL &bPointerShapeChange)
{
	for (; i < last; i++)
	{
// TODO bPointerShapeChange

		if (m_fHandleScreen2ScreenBlt && i->type == dmf_dfo_SCREEN_SCREEN)
		{
		//	DPF(("CopyRect: (%d, %d, %d, %d)\n",
		//		i->rect.left,
		//		i->rect.top,
		//		i->rect.right,
		//		i->rect.bottom));

			RECT Rc;
			Rc.left = i->rect.left + xoffset;
			Rc.top = i->rect.top + yoffset;
			Rc.right = i->rect.right + xoffset;
			Rc.bottom = i->rect.bottom + yoffset;

			POINT Pt;
			Pt.x = i->point.x + xoffset;
			Pt.y = i->point.y + yoffset;
			pDesk->CopyRect(Rc, Pt);
			continue;
		}

		if (i->type >= dmf_dfo_SCREEN_SCREEN && i->type <= dmf_dfo_TEXTOUT)
		{
		//	DPF(("XRect: (%d, %d, %d, %d)\n",
		//		i->rect.left,
		//		i->rect.top,
		//		i->rect.right,
		//		i->rect.bottom));
			rgn.AddRect(i->rect, xoffset, yoffset);
		}
	}
}

VOID	DebugPrint(PCHAR DebugMessage,
			...)
{
	va_list ap;
	va_start(ap, DebugMessage);
	TCHAR	pb[256];
	vsprintf(pb, DebugMessage, ap);
	va_end(ap);
	OutputDebugString(pb);
}
