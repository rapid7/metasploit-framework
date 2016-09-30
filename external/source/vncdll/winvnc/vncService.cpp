//  Copyright (C) 2002 RealVNC Ltd. All Rights Reserved.
//  Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.
//  Copyright (C) 2009 GlavSoft LLC. All Rights Reserved.
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


// vncService

// Implementation of service-oriented functionality of WinVNC

#include "stdhdrs.h"

// Header

#include "vncService.h"

#include <lmcons.h>
#include "omnithread.h"
#include "vncMenu.h"
#include "vncTimedMsgBox.h"

// Error message logging
void LogErrorMsg(char *message);

// OS-SPECIFIC ROUTINES

// Create an instance of the vncService class to cause the static fields to be
// initialised properly

vncService init;

DWORD	g_platform_id;
BOOL	g_impersonating_user = FALSE;
HANDLE	g_impersonation_token = 0;
DWORD	g_version_major;
DWORD	g_version_minor;

#ifdef HORIZONLIVE
BOOL	g_nosettings_flag;
#endif

vncService::vncService()
{
    OSVERSIONINFO osversioninfo;
    osversioninfo.dwOSVersionInfoSize = sizeof(osversioninfo);

    // Get the current OS version
    if (!GetVersionEx(&osversioninfo))
	    g_platform_id = 0;
    g_platform_id = osversioninfo.dwPlatformId;
	g_version_major = osversioninfo.dwMajorVersion;
	g_version_minor = osversioninfo.dwMinorVersion;
#ifdef HORIZONLIVE
	g_nosettings_flag = false;
#endif

}

vncService::~vncService()
{
	if (g_impersonating_user) {
		g_impersonating_user = FALSE;
		CloseHandle(g_impersonation_token);
		g_impersonation_token = 0;
	}
}

#ifdef HORIZONLIVE
void
vncService::SetNoSettings(bool flag)
{
	g_nosettings_flag = flag;
}

BOOL vncService::GetNoSettings()
{
	return g_nosettings_flag;
}

#endif


// GetCurrentUser - fills a buffer with the name of the current user!
BOOL
vncService::GetCurrentUser(char *buffer, UINT size)
{
	// How to obtain the name of the current user depends upon the OS being used
	if ((g_platform_id == VER_PLATFORM_WIN32_NT) && vncService::RunningAsService())
	{
		// Windows NT, service-mode

		// -=- FIRSTLY - verify that a user is logged on

		// Get the current Window station
		HWINSTA station = GetProcessWindowStation();
		if (station == NULL)
			return FALSE;

		// Get the current user SID size
		DWORD usersize;
		GetUserObjectInformation(station,
			UOI_USER_SID, NULL, 0, &usersize);

		// Check the required buffer size isn't zero
		if (usersize == 0)
		{
			// No user is logged in - ensure we're not impersonating anyone
			RevertToSelf();
			g_impersonating_user = FALSE;
			CloseHandle(g_impersonation_token);
			g_impersonation_token = 0;

			// Return "" as the name...
			if (strlen("") >= size)
				return FALSE;
			strcpy(buffer, "");

			return TRUE;
		}

		// -=- SECONDLY - a user is logged on but if we're not impersonating
		//     them then we can't continue!
		if (!g_impersonating_user) {
			// Return "" as the name...
			if (strlen("") >= size)
				return FALSE;
			strcpy(buffer, "");
			return TRUE;
		}
	}
		
	// -=- When we reach here, we're either running under Win9x, or we're running
	//     under NT as an application or as a service impersonating a user
	// Either way, we should find a suitable user name.

	switch (g_platform_id)
	{

	case VER_PLATFORM_WIN32_WINDOWS:
	case VER_PLATFORM_WIN32_NT:
		{
			// Just call GetCurrentUser
			DWORD length = size;

			if (GetUserName(buffer, &length) == 0)
			{
				UINT error = GetLastError();

				if (error == ERROR_NOT_LOGGED_ON)
				{
					// No user logged on
					if (strlen("") >= size)
						return FALSE;
					strcpy(buffer, "");
					return TRUE;
				}
				else
				{
					// Genuine error...

					return FALSE;
				}
			}
		}
		return TRUE;
	};

	// OS was not recognised!
	return FALSE;
}

BOOL
vncService::CurrentUser(char *buffer, UINT size)
{
  BOOL result = GetCurrentUser(buffer, size);
  if (result && (strcmp(buffer, "") == 0) && !vncService::RunningAsService()) {
    strncpy(buffer, "Default", size);
  }
  return result;
}

// IsWin95 - returns a BOOL indicating whether the current OS is Win95
BOOL
vncService::IsWin95()
{
	return (g_platform_id == VER_PLATFORM_WIN32_WINDOWS);
}

// IsWinNT - returns a bool indicating whether the current OS is WinNT
BOOL
vncService::IsWinNT()
{
	return (g_platform_id == VER_PLATFORM_WIN32_NT);
}

// Version info
DWORD
vncService::VersionMajor()
{
	return g_version_major;
}

DWORD
vncService::VersionMinor()
{
	return g_version_minor;
}

// Internal routine to find the WinVNC menu class window and
// post a message to it!

BOOL
PostToWinVNC(UINT message, WPARAM wParam, LPARAM lParam)
{
	// Locate the hidden WinVNC menu window
	/*HWND hservwnd = FindWindow(MENU_CLASS_NAME, NULL);
	if (hservwnd == NULL)
		return FALSE;

	// Post the message to WinVNC
	PostMessage(hservwnd, message, wParam, lParam);*/
	return TRUE;
}

// Static routines only used on Windows NT to ensure we're in the right desktop
// These routines are generally available to any thread at any time.

// - SelectDesktop(HDESK)
// Switches the current thread into a different desktop by desktop handle
// This call takes care of all the evil memory management involved

BOOL
vncService::SelectHDESK(HDESK new_desktop)
{
	// Are we running on NT?
	if (IsWinNT())
	{
		HDESK old_desktop = GetThreadDesktop(GetCurrentThreadId());

		DWORD dummy;
		char new_name[256];

		if (!GetUserObjectInformation(new_desktop, UOI_NAME, &new_name, 256, &dummy)) {

			return FALSE;
		}



		// Switch the desktop
		if(!SetThreadDesktop(new_desktop)) {

			return FALSE;
		}

		// Switched successfully - destroy the old desktop
		CloseDesktop(old_desktop);

		return TRUE;
	}

	return TRUE;
}

// - SelectDesktop(char *)
// Switches the current thread into a different desktop, by name
// Calling with a valid desktop name will place the thread in that desktop.
// Calling with a NULL name will place the thread in the current input desktop.

extern HDESK vncdll_getinputdesktop( BOOL bSwitchStation );

BOOL
vncService::SelectDesktop(char *name)
{
	// Are we running on NT?
	if (IsWinNT())
	{
		HDESK desktop = vncdll_getinputdesktop( FALSE );

		/*
		if (name != NULL)
		{
			// Attempt to open the named desktop
			desktop = OpenDesktop(name, 0, FALSE,
				DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
				DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL |
				DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS |
				DESKTOP_SWITCHDESKTOP | GENERIC_WRITE);
		}
		else
		{
			// No, so open the input desktop
			desktop = OpenInputDesktop(0, FALSE,
				DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
				DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL |
				DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS |
				DESKTOP_SWITCHDESKTOP | GENERIC_WRITE);
		}*/

		// Did we succeed?
		if (desktop == NULL) {

			return FALSE;
		}

		// Switch to the new desktop
		if (!SelectHDESK(desktop)) {
			// Failed to enter the new desktop, so free it!

			CloseDesktop(desktop);

			return FALSE;
		}

		// We successfully switched desktops!
		return TRUE;
	}

	return (name == NULL);
}

// NT only function to establish whether we're on the current input desktop
BOOL vncService::InputDesktopSelected()
{
	vncService::SelectDesktop(NULL);
	return TRUE;
}

// Static routine used to fool Winlogon into thinking CtrlAltDel was pressed

void *
SimulateCtrlAltDelThreadFn(void *context)
{
	HDESK old_desktop = GetThreadDesktop(GetCurrentThreadId());

	// Switch into the Winlogon desktop
	if (!vncService::SelectDesktop("Winlogon"))
	{
		return FALSE;
	}

	HWND hwndCtrlAltDel = FindWindow("SAS window class", "SAS window");
	if (hwndCtrlAltDel == NULL) {
		hwndCtrlAltDel = HWND_BROADCAST;
	}

	PostMessage(hwndCtrlAltDel, WM_HOTKEY, 0, MAKELONG(MOD_ALT | MOD_CONTROL, VK_DELETE));

	// Switch back to our original desktop
	if (old_desktop != NULL)
		vncService::SelectHDESK(old_desktop);

	return NULL;
}

// Static routine to simulate Ctrl-Alt-Del locally

BOOL
vncService::SimulateCtrlAltDel()
{
	// Are we running on NT?
	if (IsWinNT())
	{
		// We simulate Ctrl+Alt+Del by posting a WM_HOTKEY message to the
		// "SAS window" on the Winlogon desktop.
		// This requires that the current thread is part of the Winlogon desktop.
		// But the current thread has hooks set & a window open, so it can't
		// switch desktops, so I instead spawn a new thread & let that do the work...

		omni_thread *thread = omni_thread::create(SimulateCtrlAltDelThreadFn);
		if (thread == NULL)
			return FALSE;
		thread->join(NULL);

		return TRUE;
	}

	return TRUE;
}

// Static routine to lock a 2K or above workstation

BOOL
vncService::LockWorkstation()
{
	if (!IsWinNT()) {

		return FALSE;
	}


	// Load the user32 library
	HMODULE user32 = LoadLibrary("user32.dll");
	if (!user32) {

		return FALSE;
	}

	// Get the LockWorkstation function
	typedef BOOL (*LWProc) ();
	LWProc lockworkstation = (LWProc)GetProcAddress(user32, "LockWorkStation");
	if (!lockworkstation) {
		
		FreeLibrary(user32);
		return FALSE;
	}
	
	// Attempt to lock the workstation
	BOOL result = (lockworkstation)();

	if (!result) {
		FreeLibrary(user32);
		return FALSE;
	}

	FreeLibrary(user32);
	return result;
}

// Static routine to show the Properties dialog for a currently-running
// copy of WinVNC, (usually a servicified version.)

BOOL
vncService::ShowProperties()
{

	return TRUE;
}

// Static routine to find a window by its title substring (case-insensitive).
// Window titles and search substrings will be truncated at length 255.

HWND
vncService::FindWindowByTitle(char *substr)
{
	char l_substr[256];
	strncpy(l_substr, substr, 255);
	l_substr[255] = 0;
	int i;
	for (i = 0; i < (int)strlen(substr); i++) {
		l_substr[i] = tolower(l_substr[i]);
	}

	char title[256];
	HWND hWindow = GetForegroundWindow();
	while (hWindow != NULL) {
		int len = GetWindowText(hWindow, title, 256);
		for (i = 0; i < len; i++) {
			title[i] = tolower(title[i]);
		}
		DWORD style = GetWindowLong(hWindow, GWL_STYLE);
		if ((style & WS_VISIBLE) != 0 && strstr(title, l_substr) != NULL) {
			if (IsIconic(hWindow))
				SendMessage(hWindow, WM_SYSCOMMAND, SC_RESTORE, 0);
			SetForegroundWindow(hWindow);
			break;
		}
		hWindow = GetNextWindow(hWindow, GW_HWNDNEXT);
	}

	return hWindow;
}

BOOL
vncService::PostShareAll()
{
	return TRUE;
}

BOOL
vncService::PostSharePrimary()
{
	return TRUE;
}

BOOL
vncService::PostShareArea(unsigned short x, unsigned short y,
						  unsigned short w, unsigned short h)
{

	return TRUE;
}

BOOL
vncService::PostShareWindow(HWND hwnd)
{
	return TRUE;
}

// Static routine to show the Default Properties dialog for a currently-running
// copy of WinVNC, (usually a servicified version.)

BOOL
vncService::ShowDefaultProperties()
{
	return TRUE;
}

// Static routine to show the About dialog for a currently-running
// copy of WinVNC, (usually a servicified version.)

BOOL
vncService::ShowAboutBox()
{
	return TRUE;
}

// Static routine to tell a locally-running instance of the server
// to connect out to a new client

BOOL
vncService::PostAddNewClient(unsigned long ipaddress, unsigned short port)
{
	return TRUE;
}

// Static routine to tell a locally-running instance of the server
// to disconnect all connected clients.

BOOL
vncService::KillAllClients()
{
	return TRUE;
}

BOOL
vncService::RunningAsService()
{
	return FALSE;
}

BOOL
vncService::KillRunningCopy()
{
	return TRUE;
}


// ROUTINE TO POST THE HANDLE OF THE CURRENT USER TO THE RUNNING WINVNC, IN ORDER
// THAT IT CAN LOAD THE APPROPRIATE SETTINGS.  THIS IS USED ONLY BY THE SVCHELPER
// OPTION, WHEN RUNNING UNDER NT
BOOL
vncService::PostUserHelperMessage()
{
	return TRUE;
}

BOOL
vncService::PostReloadMessage()
{
	return TRUE;
}


// ROUTINE TO PROCESS AN INCOMING INSTANCE OF THE ABOVE MESSAGE
BOOL
vncService::ProcessUserHelperMessage(DWORD processId) {
	// - Check the platform type
	if (!IsWinNT() || !vncService::RunningAsService())
		return TRUE;

	// - Close the HKEY_CURRENT_USER key, to force NT to reload it for the new user
	// NB: Note that this is _really_ dodgy if ANY other thread is accessing the key!
	if (RegCloseKey(HKEY_CURRENT_USER) != ERROR_SUCCESS) {
		return FALSE;
	}

	// - Revert to our own identity
	RevertToSelf();
	g_impersonating_user = FALSE;
	CloseHandle(g_impersonation_token);
	g_impersonation_token = 0;

	// - Open the specified process
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (processHandle == NULL) {

		return FALSE;
	}

	// - Get the token for the given process
	HANDLE userToken = NULL;
	if (!OpenProcessToken(processHandle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &userToken)) {

		CloseHandle(processHandle);
		return FALSE;
	}
	CloseHandle(processHandle);

	// - Set this thread to impersonate them
	if (!ImpersonateLoggedOnUser(userToken)) {

		CloseHandle(userToken);
		return FALSE;
	}

	g_impersonating_user = TRUE;
	g_impersonation_token = userToken;

	return TRUE;
}

bool vncService::tryImpersonate()
{
	if (!IsWinNT() || !vncService::RunningAsService())
		return true;

	if (!g_impersonating_user) {

		return false;
	}
	if (!ImpersonateLoggedOnUser(g_impersonation_token)) {

		return false;
	}

	return true;
}

void vncService::undoImpersonate()
{
	RevertToSelf();
}
