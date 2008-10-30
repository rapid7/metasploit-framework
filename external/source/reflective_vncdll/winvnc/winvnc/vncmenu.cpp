//  Copyright (C) 2002-2003 RealVNC Ltd. All Rights Reserved.
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
// If the source code for the VNC system is not available from the place 
// whence you received this file, check http://www.uk.research.att.com/vnc or contact
// the authors on vnc@uk.research.att.com for information on obtaining it.


// vncMenu

// Implementation of a system tray icon & menu for WinVNC

#include "stdhdrs.h"
#include "WinVNC.h"
#include "vncService.h"
#include "vncConnDialog.h"
#include <lmcons.h>
#include <wininet.h>
#include <shlobj.h>

// Header

#include "vncMenu.h"

// Constants
const UINT MENU_PROPERTIES_SHOW = RegisterWindowMessage("WinVNC.Properties.User.Show");
const UINT MENU_DEFAULT_PROPERTIES_SHOW = RegisterWindowMessage("WinVNC.Properties.Default.Show");
const UINT MENU_ABOUTBOX_SHOW = RegisterWindowMessage("WinVNC.AboutBox.Show");
const UINT MENU_SERVICEHELPER_MSG = RegisterWindowMessage("WinVNC.ServiceHelper.Message");
const UINT MENU_ADD_CLIENT_MSG = RegisterWindowMessage("WinVNC.AddClient.Message");
const UINT MENU_REMOVE_CLIENTS_MSG = RegisterWindowMessage("WinVNC.RemoveClients.Message");
const char *MENU_CLASS_NAME = "WinVNC Tray Icon";

bool g_restore_ActiveDesktop = false;

static void
KillActiveDesktop()
{
  //vnclog.Print(LL_INTERR, VNCLOG("KillActiveDesktop\n"));

  // Contact Active Desktop if possible
  HRESULT result;
  IActiveDesktop* active_desktop = 0;
  result = CoCreateInstance(CLSID_ActiveDesktop, NULL, CLSCTX_INPROC_SERVER,
    IID_IActiveDesktop, (void**)&active_desktop);
  if (result != S_OK) {
    //vnclog.Print(LL_INTERR, VNCLOG("unable to access Active Desktop object:%x\n"), result);
    return;
  }

  // Get Active Desktop options
  COMPONENTSOPT options;
  options.dwSize = sizeof(options);
  result = active_desktop->GetDesktopItemOptions(&options, 0);
  if (result != S_OK) {
    //vnclog.Print(LL_INTERR, VNCLOG("unable to fetch Active Desktop options:%x\n"), result);
    active_desktop->Release();
    return;
  }

  // Disable if currently active
  g_restore_ActiveDesktop = options.fActiveDesktop;
  if (options.fActiveDesktop) {
    //vnclog.Print(LL_INTINFO, VNCLOG("attempting to disable Active Desktop\n"));
    options.fActiveDesktop = FALSE;
    result = active_desktop->SetDesktopItemOptions(&options, 0);
    if (result != S_OK) {
      //vnclog.Print(LL_INTERR, VNCLOG("unable to disable Active Desktop:%x\n"), result);
      active_desktop->Release();
      return;
    }
  }// else {
  //  //vnclog.Print(LL_INTINFO, VNCLOG("Active Desktop not enabled - ignoring\n"));
  //}

  active_desktop->ApplyChanges(AD_APPLY_REFRESH);
  active_desktop->Release();
}

static void
KillWallpaper()
{
  KillActiveDesktop();

	// Tell all applications that there is no wallpaper
	// Note that this doesn't change the wallpaper registry setting!
	SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, "", SPIF_SENDCHANGE);
}

static void
RestoreActiveDesktop()
{
  // Contact Active Desktop if possible
  HRESULT result;
  IActiveDesktop* active_desktop = 0;
  result = CoCreateInstance(CLSID_ActiveDesktop, NULL, CLSCTX_INPROC_SERVER,
    IID_IActiveDesktop, (void**)&active_desktop);
  if (result != S_OK) {
    //vnclog.Print(LL_INTERR, VNCLOG("unable to access Active Desktop object:%x\n"), result);
    return;
  }

  // Get Active Desktop options
  COMPONENTSOPT options;
  options.dwSize = sizeof(options);
  result = active_desktop->GetDesktopItemOptions(&options, 0);
  if (result != S_OK) {
    //vnclog.Print(LL_INTERR, VNCLOG("unable to fetch Active Desktop options:%x\n"), result);
    active_desktop->Release();
    return;
  }

  // Re-enable if previously disabled
  if (g_restore_ActiveDesktop) {
    g_restore_ActiveDesktop = false;
    //vnclog.Print(LL_INTINFO, VNCLOG("attempting to re-enable Active Desktop\n"));
    options.fActiveDesktop = TRUE;
    result = active_desktop->SetDesktopItemOptions(&options, 0);
    if (result != S_OK) {
      //vnclog.Print(LL_INTERR, VNCLOG("unable to re-enable Active Desktop:%x\n"), result);
      active_desktop->Release();
      return;
    }
  }

  active_desktop->ApplyChanges(AD_APPLY_REFRESH);
  active_desktop->Release();
}

static void
RestoreWallpaper()
{
  RestoreActiveDesktop();
	SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, NULL, SPIF_SENDCHANGE);
}

// Implementation

vncMenu::vncMenu(vncServer *server)
{
  CoInitialize(0);

	// Save the server pointer
	m_server = server;

	// Set the initial user name to something sensible...
	vncService::CurrentUser((char *)&m_username, sizeof(m_username));

	// Create a dummy window to handle tray icon messages
	WNDCLASSEX wndclass;

	wndclass.cbSize			= sizeof(wndclass);
	wndclass.style			= 0;
	wndclass.lpfnWndProc	= vncMenu::WndProc;
	wndclass.cbClsExtra		= 0;
	wndclass.cbWndExtra		= 0;
	wndclass.hInstance		= hAppInstance;
	wndclass.hIcon			= LoadIcon(NULL, IDI_APPLICATION);
	wndclass.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wndclass.hbrBackground	= (HBRUSH) GetStockObject(WHITE_BRUSH);
	wndclass.lpszMenuName	= (const char *) NULL;
	wndclass.lpszClassName	= MENU_CLASS_NAME;
	wndclass.hIconSm		= LoadIcon(NULL, IDI_APPLICATION);

	RegisterClassEx(&wndclass);

	m_hwnd = CreateWindow(MENU_CLASS_NAME,
				MENU_CLASS_NAME,
				WS_OVERLAPPEDWINDOW,
				CW_USEDEFAULT,
				CW_USEDEFAULT,
				200, 200,
				NULL,
				NULL,
				hAppInstance,
				NULL);
	if (m_hwnd == NULL)
	{
    //vnclog.Print(LL_INTERR, VNCLOG("unable to CreateWindow:%d\n"), GetLastError());
		PostQuitMessage(0);
		return;
	}

	// Timer to trigger icon updating
	SetTimer(m_hwnd, 1, 5000, NULL);

	// record which client created this window
	SetWindowLong(m_hwnd, GWL_USERDATA, (LONG) this);

	// Ask the server object to notify us of stuff
	server->AddNotify(m_hwnd);

	// Initialise the properties dialog object
	if (!m_properties.Init(m_server))
	{
    //vnclog.Print(LL_INTERR, VNCLOG("unable to initialise Properties dialog\n"));
		PostQuitMessage(0);
		return;
	}

	// Load the icons for the tray
	m_winvnc_icon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_WINVNC));
	m_flash_icon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_FLASH));

	// Load the popup menu
	m_hmenu = LoadMenu(hAppInstance, MAKEINTRESOURCE(IDR_TRAYMENU));

	// Install the tray icon! XXX
	//AddTrayIcon();
}

vncMenu::~vncMenu()
{
	// Remove the tray icon
	DelTrayIcon();
	
	// Destroy the loaded menu
	if (m_hmenu != NULL)
		DestroyMenu(m_hmenu);

	// Tell the server to stop notifying us!
	if (m_server != NULL)
		m_server->RemNotify(m_hwnd);
}

void
vncMenu::AddTrayIcon()
{
	// If the user name is non-null then we have a user!
	if (strcmp(m_username, "") != 0)
		SendTrayMsg(NIM_ADD, FALSE);
}

void
vncMenu::DelTrayIcon()
{
	SendTrayMsg(NIM_DELETE, FALSE);
}

void
vncMenu::FlashTrayIcon(BOOL flash)
{
	SendTrayMsg(NIM_MODIFY, flash);
}

// Get the local ip addresses as a human-readable string.
// If more than one, then with \n between them.
// If not available, then gets a message to that effect.
void GetIPAddrString(char *buffer, int buflen) {
    char namebuf[256];

    if (gethostname(namebuf, 256) != 0) {
		strncpy(buffer, "Host name unavailable", buflen);
		return;
    };

    HOSTENT *ph = gethostbyname(namebuf);
    if (!ph) {
		strncpy(buffer, "IP address unavailable", buflen);
		return;
    };

    *buffer = '\0';
    char digtxt[5];
    for (int i = 0; ph->h_addr_list[i]; i++) {
    	for (int j = 0; j < ph->h_length; j++) {
			sprintf(digtxt, "%d.", (unsigned char) ph->h_addr_list[i][j]);
			strncat(buffer, digtxt, (buflen-1)-strlen(buffer));
		}	
		buffer[strlen(buffer)-1] = '\0';
		if (ph->h_addr_list[i+1] != 0)
			strncat(buffer, ", ", (buflen-1)-strlen(buffer));
    }
}

void
vncMenu::SendTrayMsg(DWORD msg, BOOL flash)
{
	// Create the tray icon message
	m_nid.hWnd = m_hwnd;
	m_nid.cbSize = sizeof(m_nid);
	m_nid.uID = IDI_WINVNC;			// never changes after construction
	m_nid.hIcon = flash ? m_flash_icon : m_winvnc_icon;
	m_nid.uFlags = NIF_ICON | NIF_MESSAGE;
	m_nid.uCallbackMessage = WM_TRAYNOTIFY;

	// Use resource string as tip if there is one
	if (LoadString(hAppInstance, IDI_WINVNC, m_nid.szTip, sizeof(m_nid.szTip)))
	{
	    m_nid.uFlags |= NIF_TIP;
	}
	
	// Try to add the server's IP addresses to the tip string, if possible
	if (m_nid.uFlags & NIF_TIP)
	{
	    strncat(m_nid.szTip, " - ", (sizeof(m_nid.szTip)-1)-strlen(m_nid.szTip));

	    if (m_server->SockConnected())
	    {
		unsigned long tiplen = strlen(m_nid.szTip);
		char *tipptr = ((char *)&m_nid.szTip) + tiplen;

		GetIPAddrString(tipptr, sizeof(m_nid.szTip) - tiplen);
	    }
	    else
	    {
		strncat(m_nid.szTip, "Not listening", (sizeof(m_nid.szTip)-1)-strlen(m_nid.szTip));
	    }
	}

	// Send the message
	if (Shell_NotifyIcon(msg, &m_nid))
	{
		// Set the enabled/disabled state of the menu items
		//vnclog.Print(LL_INTINFO, VNCLOG("tray icon added ok\n"));

		EnableMenuItem(m_hmenu, ID_PROPERTIES,
			m_properties.AllowProperties() ? MF_ENABLED : MF_GRAYED);
		EnableMenuItem(m_hmenu, ID_CLOSE,
			m_properties.AllowShutdown() ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(m_hmenu, ID_KILLCLIENTS,
			m_properties.AllowEditClients() ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(m_hmenu, ID_OUTGOING_CONN,
			m_properties.AllowEditClients() ? MF_ENABLED : MF_GRAYED);
	} else {
		if (!vncService::RunningAsService())
		{
			if (msg == NIM_ADD)
			{
				// The tray icon couldn't be created, so use the Properties dialog
				// as the main program window
				//vnclog.Print(LL_INTINFO, VNCLOG("opening dialog box\n"));
				m_properties.Show(TRUE, TRUE);
        //vnclog.Print(LL_INTERR, VNCLOG("unable to add tray icon\n"), GetLastError());
				PostQuitMessage(0);
			}
		}
	}
}

// Process window messages
LRESULT CALLBACK vncMenu::WndProc(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	// This is a static method, so we don't know which instantiation we're 
	// dealing with. We use Allen Hadden's (ahadden@taratec.com) suggestion 
	// from a newsgroup to get the pseudo-this.
	vncMenu *_this = (vncMenu *) GetWindowLong(hwnd, GWL_USERDATA);

	switch (iMsg)
	{

		// Every five seconds, a timer message causes the icon to update
	case WM_TIMER:
	    // *** HACK for running servicified
		if (vncService::RunningAsService()) {
		    // Attempt to add the icon if it's not already there
		    _this->AddTrayIcon();
		    // Trigger a check of the current user
		    PostMessage(hwnd, WM_USERCHANGED, 0, 0);
		}

		// Update the icon
		_this->FlashTrayIcon(_this->m_server->AuthClientCount() != 0);
		break;

		// DEAL WITH NOTIFICATIONS FROM THE SERVER:
	case WM_SRV_CLIENT_AUTHENTICATED:
	case WM_SRV_CLIENT_DISCONNECT:
		// Adjust the icon accordingly
		_this->FlashTrayIcon(_this->m_server->AuthClientCount() != 0);

		if (_this->m_server->AuthClientCount() != 0) {
			if (_this->m_server->RemoveWallpaperEnabled())
				KillWallpaper();
		} else {
			RestoreWallpaper();
		}
		return 0;

		// STANDARD MESSAGE HANDLING
	case WM_CREATE:
		return 0;

	case WM_COMMAND:
		// User has clicked an item on the tray menu
		switch (LOWORD(wParam))
		{

		case ID_DEFAULT_PROPERTIES:
			// Show the default properties dialog, unless it is already displayed
			//vnclog.Print(LL_INTINFO, VNCLOG("show default properties requested\n"));
			_this->m_properties.Show(TRUE, FALSE);
			_this->FlashTrayIcon(_this->m_server->AuthClientCount() != 0);
			break;
		

		case ID_PROPERTIES:
			// Show the properties dialog, unless it is already displayed
			//vnclog.Print(LL_INTINFO, VNCLOG("show user properties requested\n"));
			_this->m_properties.Show(TRUE, TRUE);
			_this->FlashTrayIcon(_this->m_server->AuthClientCount() != 0);
			break;
		
		case ID_OUTGOING_CONN:
			// Connect out to a listening VNC viewer
			{
				vncConnDialog *newconn = new vncConnDialog(_this->m_server);
				if (newconn)
					newconn->DoDialog();
			}
			break;

		case ID_KILLCLIENTS:
			// Disconnect all currently connected clients
			_this->m_server->KillAuthClients();
			break;

		case ID_ABOUT:
			// Show the About box
			_this->m_about.Show(TRUE);
			break;

		case ID_CLOSE:
			// User selected Close from the tray menu
			PostMessage(hwnd, WM_CLOSE, 0, 0);
			break;

		}
		return 0;

	case WM_TRAYNOTIFY:
		// User has clicked on the tray icon or the menu
		{
			// Get the submenu to use as a pop-up menu
			HMENU submenu = GetSubMenu(_this->m_hmenu, 0);

			// What event are we responding to, RMB click?
			if (lParam==WM_RBUTTONUP)
			{
				if (submenu == NULL)
				{ 
					//vnclog.Print(LL_INTERR, VNCLOG("no submenu available\n"));
					return 0;
				}

				// Make the first menu item the default (bold font)
				SetMenuDefaultItem(submenu, 0, TRUE);
				
				// Get the current cursor position, to display the menu at
				POINT mouse;
				GetCursorPos(&mouse);

				// There's a "bug"
				// (Microsoft calls it a feature) in Windows 95 that requires calling
				// SetForegroundWindow. To find out more, search for Q135788 in MSDN.
				//
				SetForegroundWindow(_this->m_nid.hWnd);

				// Display the menu at the desired position
				TrackPopupMenu(submenu,
						0, mouse.x, mouse.y, 0,
						_this->m_nid.hWnd, NULL);

				return 0;
			}
			
			// Or was there a LMB double click?
			if (lParam==WM_LBUTTONDBLCLK)
			{
				// double click: execute first menu item
				SendMessage(_this->m_nid.hWnd,
							WM_COMMAND, 
							GetMenuItemID(submenu, 0),
							0);
			}

			return 0;
		}

	case WM_CLOSE:

		// Only accept WM_CLOSE if the logged on user has AllowShutdown set
		if (!_this->m_properties.AllowShutdown())
			return 0;
		break;

	case WM_DESTROY:
		// The user wants WinVNC to quit cleanly...
		//vnclog.Print(LL_INTERR, VNCLOG("quitting from WM_DESTROY\n"));
		PostQuitMessage(0);
		return 0;

  case WM_QUERYENDSESSION:
    //vnclog.Print(LL_INTERR, VNCLOG("WM_QUERYENDSESSION\n"));
    break;

  case WM_ENDSESSION:
    //vnclog.Print(LL_INTERR, VNCLOG("WM_ENDSESSION\n"));
    break;

/*
	case WM_ENDSESSION:
		// Are we running as a system service, or shutting the system down?
		if (wParam && (lParam == 0))
		{
			// Shutdown!
			// Try to clean ourselves up nicely, if possible...

			// Firstly, disable incoming CORBA or socket connections
			_this->m_server->SockConnect(FALSE);
			_this->m_server->CORBAConnect(FALSE);

			// Now kill all the server's clients
			_this->m_server->KillAuthClients();
			_this->m_server->KillUnauthClients();
			_this->m_server->WaitUntilAuthEmpty();
			_this->m_server->WaitUntilUnauthEmpty();
		}

		// Tell the OS that we've handled it anyway
		return 0;
		*/

	case WM_USERCHANGED:
		// The current user may have changed.
		{
			char newuser[UNLEN+1];

			if (vncService::CurrentUser((char *) &newuser, sizeof(newuser)))
			{
				//vnclog.Print(LL_INTINFO,
				//	VNCLOG("usernames : old=\"%s\", new=\"%s\"\n"),
				//	_this->m_username, newuser);

				// Check whether the user name has changed!
				if (strcmp(newuser, _this->m_username) != 0)
				{
					//vnclog.Print(LL_INTINFO,
					//	VNCLOG("user name has changed\n"));

					// User has changed!
					strcpy(_this->m_username, newuser);

					// Redraw the tray icon and set it's state
					_this->DelTrayIcon();
					_this->AddTrayIcon();
					_this->FlashTrayIcon(_this->m_server->AuthClientCount() != 0);

					// We should load in the prefs for the new user
					_this->m_properties.Load(TRUE);
				}
			}
		}
		return 0;
	
	default:
		// Deal with any of our custom message types
		if (iMsg == MENU_PROPERTIES_SHOW)
		{
			// External request to show our Properties dialog
			PostMessage(hwnd, WM_COMMAND, MAKELONG(ID_PROPERTIES, 0), 0);
			return 0;
		}
		if (iMsg == MENU_DEFAULT_PROPERTIES_SHOW)
		{
			// External request to show our Properties dialog
			PostMessage(hwnd, WM_COMMAND, MAKELONG(ID_DEFAULT_PROPERTIES, 0), 0);
			return 0;
		}
		if (iMsg == MENU_ABOUTBOX_SHOW)
		{
			// External request to show our About dialog
			PostMessage(hwnd, WM_COMMAND, MAKELONG(ID_ABOUT, 0), 0);
			return 0;
		}
		if (iMsg == MENU_SERVICEHELPER_MSG)
		{
			// External ServiceHelper message.
			// This message holds a process id which we can use to
			// impersonate a specific user.  In doing so, we can load their
			// preferences correctly
			vncService::ProcessUserHelperMessage(wParam, lParam);

			// - Trigger a check of the current user
			PostMessage(hwnd, WM_USERCHANGED, 0, 0);
			return 0;
		}
		if (iMsg == MENU_ADD_CLIENT_MSG)
		{
			// Add Client message.  This message includes an IP address
			// of a listening client, to which we should connect.

			// If there is no IP address then show the connection dialog
			if (!lParam) {
				vncConnDialog *newconn = new vncConnDialog(_this->m_server);
				if (newconn) newconn->DoDialog();
				return 0;
			}

			// Get the IP address stringified
			struct in_addr address;
			address.S_un.S_addr = lParam;
			char *name = inet_ntoa(address);
			if (name == 0)
				return 0;
			char *nameDup = strdup(name);
			if (nameDup == 0)
				return 0;

			// Attempt to create a new socket
			VSocket *tmpsock;
			tmpsock = new VSocket;
			if (tmpsock) {

				// Connect out to the specified host on the VNCviewer listen port
				tmpsock->Create();
				if (tmpsock->Connect(nameDup, INCOMING_PORT_OFFSET)) {
					// Add the new client to this server
					_this->m_server->AddClient(tmpsock, TRUE, TRUE);
				} else {
					delete tmpsock;
				}
			}

			// Free the duplicate name
			free(nameDup);
			return 0;
		}
		if (iMsg == MENU_REMOVE_CLIENTS_MSG)
		{
      // Kill all connected clients
      _this->m_server->KillAuthClients();
    }
	}

	// Message not recognised
	return DefWindowProc(hwnd, iMsg, wParam, lParam);
}
