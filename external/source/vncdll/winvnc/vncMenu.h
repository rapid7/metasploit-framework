//  Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.
//
//  This file is part of the VNC system.
//
//  The VNC system is free software; you can redistribute it and/or modify
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
//
// If the source code for the VNC system is not available from the place 
// whence you received this file, check http://www.uk.research.att.com/vnc or contact
// the authors on vnc@uk.research.att.com for information on obtaining it.


// vncMenu

// This class handles creation of a system-tray icon & menu

#ifdef HORIZONLIVE
#include "horizon/horizonMenu.h"
#else

class vncMenu;

#if (!defined(_WINVNC_VNCMENU))
#define _WINVNC_VNCMENU

#include "stdhdrs.h"
#include <lmcons.h>
#include "vncServer.h"
#include "vncProperties.h"
#include "vncAbout.h"
#include "WallpaperUtils.h"

// Constants
extern const UINT MENU_SERVER_SHAREALL;
extern const UINT MENU_SERVER_SHAREPRIMARY;
extern const UINT MENU_SERVER_SHAREAREA;
extern const UINT MENU_SERVER_SHAREWINDOW;
extern const UINT MENU_PROPERTIES_SHOW;
extern const UINT MENU_DEFAULT_PROPERTIES_SHOW;
extern const UINT MENU_ABOUTBOX_SHOW;
extern const UINT MENU_SERVICEHELPER_MSG;
extern const UINT MENU_RELOAD_MSG;
extern const UINT MENU_ADD_CLIENT_MSG;
extern const UINT MENU_KILL_ALL_CLIENTS_MSG;
extern const char *MENU_CLASS_NAME;

extern const UINT fileTransferDownloadMessage;

// The tray menu class itself
class vncMenu
{
public:
	vncMenu(vncServer *server);
	~vncMenu();
protected:
	// Tray icon handling
	void AddTrayIcon();
	void DelTrayIcon();
	void FlashTrayIcon(BOOL flash);
	void SendTrayMsg(DWORD msg, BOOL flash);

	// Message handler for the tray window
	static LRESULT CALLBACK WndProc(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam);

	// Fields
protected:
	// The server that this tray icon handles
	vncServer		*m_server;

	// Properties object for this server
	vncProperties	m_properties;

	// About dialog for this server
	vncAbout		m_about;

	// The object to hide/show wallpaper and ActiveDesktop
	WallpaperUtils	m_wputils;

	HWND			m_hwnd;
	HMENU			m_hmenu;
	NOTIFYICONDATA		m_nid;

	char			m_username[UNLEN+1];

	// The icon handles
	HICON			m_winvnc_normal_icon;
	HICON			m_winvnc_disabled_icon;
	HICON			m_flash_icon;
};


#endif // _WINVNC_VNCMENU
#endif // HORIZONLIVE
