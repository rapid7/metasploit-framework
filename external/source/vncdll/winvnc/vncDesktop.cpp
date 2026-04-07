//  Copyright (C) 2001-2004 HorizonLive.com, Inc. All Rights Reserved.
//  Copyright (C) 2001-2004 TightVNC Team. All Rights Reserved.
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

// vncDesktop implementation

// System headers
#include "stdhdrs.h"
#include <omnithread.h>

// Custom headers
#include "vncServer.h"
#include "vncRegion.h"
#include "rectlist.h"
#include "vncDesktop.h"
#include "vncService.h"
#include "WallpaperUtils.h"
#include "TsSessions.h"

#if (_MSC_VER>= 1300)
#include <fstream>
#else
#include <fstream.h>
#endif

extern HINSTANCE hAppInstance;

// Constants
const UINT RFB_SCREEN_UPDATE = RegisterWindowMessage("WinVNC.Update.DrawRect");
const UINT RFB_COPYRECT_UPDATE = RegisterWindowMessage("WinVNC.Update.CopyRect");
const UINT RFB_MOUSE_UPDATE = RegisterWindowMessage("WinVNC.Update.Mouse");
// Messages for blocking remote input events
const UINT RFB_LOCAL_KEYBOARD = RegisterWindowMessage("WinVNC.Local.Keyboard");
const UINT RFB_LOCAL_MOUSE = RegisterWindowMessage("WinVNC.Local.Mouse");

const char szDesktopSink[] = "WinVNC desktop sink";

// Atoms
const char *VNC_WINDOWPOS_ATOMNAME = "VNCHooks.CopyRect.WindowPos";
ATOM VNC_WINDOWPOS_ATOM = NULL;

// Static members to use with new polling algorithm
const int vncDesktop::m_pollingOrder[32] = {
	 0, 16,  8, 24,  4, 20, 12, 28,
	10, 26, 18,  2, 22,  6, 30, 14,
	 1, 17,  9, 25,  7, 23, 15, 31,
	19,  3, 27, 11, 29, 13,  5, 21
};
int vncDesktop::m_pollingStep = 0;


BOOL IsWinNT()
{
	return vncService::IsWinNT();
}

BOOL IsWinVerOrHigher(ULONG mj, ULONG mn)
{
	return vncService::VersionMajor() > mj ||
		vncService::VersionMajor() == mj && vncService::VersionMinor() >= mn;
}

BOOL IsNtVer(ULONG mj, ULONG mn)
{
	if (!vncService::IsWinNT())	
		return FALSE;
	return vncService::VersionMajor() == mj && vncService::VersionMinor() == mn;
}

BOOL vncDesktop::IsMultiMonDesktop()
{
	if (!IsWinVerOrHigher(4, 10))
		return FALSE;
	return GetSystemMetrics(SM_CMONITORS) > 1;
}

// The desktop handler thread
// This handles the messages posted by RFBLib to the vncDesktop window

class vncDesktopThread : public omni_thread
{
public:
	vncDesktopThread() { m_returnsig = NULL; }
protected:
	~vncDesktopThread() { if (m_returnsig != NULL) delete m_returnsig; }
public:
	virtual BOOL Init(vncDesktop *desktop, vncServer *server);
	virtual void *run_undetached(void *arg);
	virtual void ReturnVal(BOOL result);

protected:
	vncServer *m_server;
	vncDesktop *m_desktop;

	omni_mutex m_returnLock;
	omni_condition *m_returnsig;
	BOOL m_return;
	BOOL m_returnset;
};

BOOL
vncDesktopThread::Init(vncDesktop *desktop, vncServer *server)
{
	// Save the server pointer
	m_server = server;
	m_desktop = desktop;

	m_returnset = FALSE;
	m_returnsig = new omni_condition(&m_returnLock);

	// Start the thread
	start_undetached();

	// Wait for the thread to let us know if it failed to init
	{	omni_mutex_lock l(m_returnLock);

		while (!m_returnset)
		{
			m_returnsig->wait();
		}
	}

	return m_return;
}

void
vncDesktopThread::ReturnVal(BOOL result)
{
	omni_mutex_lock l(m_returnLock);

	m_returnset = TRUE;
	m_return = result;
	m_returnsig->signal();
}

void *vncDesktopThread::run_undetached(void *arg)
{
	// Save the thread's "home" desktop, under NT (no effect under 9x)
	HDESK home_desktop = GetThreadDesktop(GetCurrentThreadId());

	// Try to make session zero the console session
	if (!inConsoleSession())
		setConsoleSession();

	// Attempt to initialise and return success or failure
	if (!m_desktop->Startup())
	{
// vncDesktop::Startup might mave changed video mode in SetupDisplayForConnection.
// it has to be reverted then.
// TODO: review strong guarantee conditions for vncDesktop::Startup
		m_desktop->ResetDisplayToNormal();
		vncService::SelectHDESK(home_desktop);
		ReturnVal(FALSE);
		return NULL;
	}

	RECT rect = m_desktop->GetSourceRect();
	IntersectRect(&rect, &rect, &m_desktop->m_bmrect);
	m_server->SetSharedRect(rect);

	// Succeeded to initialise ok
	ReturnVal(TRUE);

	// START PROCESSING DESKTOP MESSAGES

	// We set a flag inside the desktop handler here, to indicate it's now safe
	// to handle clipboard messages
	m_desktop->SetClipboardActive(TRUE);

	SYSTEMTIME systime;
	FILETIME ftime;
	ULARGE_INTEGER now, droptime;
	droptime.QuadPart = 0;

	MSG msg;
	while (TRUE)
	{
		if (!PeekMessage(&msg, m_desktop->Window(), NULL, NULL, PM_REMOVE))
		{
			// Whenever the message queue becomes empty, we check to see whether
			// there are updates to be passed to clients (first we make sure
			// that scheduled wallpaper removal is complete).
			if (!m_server->WallpaperWait()) {
				if (!m_desktop->CheckUpdates())
					break;
			}

			// Now wait for more messages to be queued
			if (!WaitMessage())
			{

				break;
			}
		}
		else if (msg.message == RFB_SCREEN_UPDATE)
		{
// TODO: suppress this message from hook when driver is active

			// An area of the screen has changed (ignore if we have a driver)
			if (m_desktop->m_videodriver == NULL)
			{
				RECT rect;
				rect.left =	(SHORT)LOWORD(msg.wParam);
				rect.top = (SHORT)HIWORD(msg.wParam);
				rect.right = (SHORT)LOWORD(msg.lParam);
				rect.bottom = (SHORT)HIWORD(msg.lParam);
				m_desktop->m_changed_rgn.AddRect(rect);
			}
		}
		else if (msg.message == RFB_MOUSE_UPDATE)
		{
			// Save the cursor ID
			m_desktop->SetCursor((HCURSOR) msg.wParam);
		}
		else if (msg.message == RFB_LOCAL_KEYBOARD)
		{
			// Block remote input events if necessary
			if (vncService::IsWin95()) {
				m_server->SetKeyboardCounter(-1);
				if (m_server->KeyboardCounter() < 0) {
					GetSystemTime(&systime);
					SystemTimeToFileTime(&systime, &ftime);
					droptime.LowPart = ftime.dwLowDateTime; 
					droptime.HighPart = ftime.dwHighDateTime;
					droptime.QuadPart /= 10000000;	// convert into seconds
					m_server->BlockRemoteInput(true);
				}
			} else {
				GetSystemTime(&systime);
				SystemTimeToFileTime(&systime, &ftime);
				droptime.LowPart = ftime.dwLowDateTime; 
				droptime.HighPart = ftime.dwHighDateTime;
				droptime.QuadPart /= 10000000;	// convert into seconds
				m_server->BlockRemoteInput(true);
			}
		}
		else if (msg.message == RFB_LOCAL_MOUSE)
		{
			// Block remote input events if necessary
			if (vncService::IsWin95()) {
				if (msg.wParam == WM_MOUSEMOVE) {
					m_server->SetMouseCounter(-1, msg.pt, true);
				} else {
					m_server->SetMouseCounter(-1, msg.pt, false);
				}
				if (m_server->MouseCounter() < 0 && droptime.QuadPart == 0) {
					GetSystemTime(&systime);
					SystemTimeToFileTime(&systime, &ftime);
					droptime.LowPart = ftime.dwLowDateTime; 
					droptime.HighPart = ftime.dwHighDateTime;
					droptime.QuadPart /= 10000000;	// convert into seconds
					m_server->BlockRemoteInput(true);
				}
			} else {
				GetSystemTime(&systime);
				SystemTimeToFileTime(&systime, &ftime);
				droptime.LowPart = ftime.dwLowDateTime; 
				droptime.HighPart = ftime.dwHighDateTime;
				droptime.QuadPart /= 10000000;	// convert into seconds
				m_server->BlockRemoteInput(true);
			}
		}
		else if (msg.message == WM_QUIT)
		{
			break;
		}
#ifdef HORIZONLIVE
		else if (msg.message == LS_QUIT)
		{
			// this is our custom quit message
			break;
		}
#endif
		else
		{
			// Process any other messages normally
			DispatchMessage(&msg);
		}

		// Check timer to unblock remote input events if necessary
		// FIXME: rewrite this stuff to eliminate code duplication (ses above).
		// FIXME: Use time() instead of GetSystemTime().
		// FIXME: It's not necessary to do this on receiving _each_ message.
		if (m_server->LocalInputPriority() && droptime.QuadPart != 0) {
			GetSystemTime(&systime);
			SystemTimeToFileTime(&systime, &ftime);
			now.LowPart = ftime.dwLowDateTime;
			now.HighPart = ftime.dwHighDateTime;
			now.QuadPart /= 10000000;	// convert into seconds

			if (now.QuadPart - m_server->DisableTime() >= droptime.QuadPart) {
				m_server->BlockRemoteInput(false);
				droptime.QuadPart = 0;
				m_server->SetKeyboardCounter(0);
				m_server->SetMouseCounter(0, msg.pt, false);
			}
		}
	}

	m_desktop->SetClipboardActive(FALSE);
	
	// Clear all the hooks and close windows, etc.
	m_desktop->Shutdown();
	// Return display settings to previous values.
	m_desktop->ResetDisplayToNormal();
	// Turn on the screen.
	m_desktop->BlankScreen(FALSE);

	// Clear the shift modifier keys, now that there are no remote clients
	vncKeymap::ClearShiftKeys();

	// Switch back into our home desktop, under NT (no effect under 9x)
	vncService::SelectHDESK(home_desktop);

	return NULL;
}

// Implementation of the vncDesktop class

vncDesktop::vncDesktop()
{
	m_thread = NULL;

	m_hwnd = NULL;
	m_polling_flag = FALSE;
	m_timer_polling = 0;
	m_timer_blank_screen = 0;
	m_hnextviewer = NULL;
	m_hcursor = NULL;

	m_displaychanged = FALSE;

	m_hrootdc = NULL;
	m_hmemdc = NULL;
	m_membitmap = NULL;

	m_initialClipBoardSeen = FALSE;

	// Vars for Will Dean's DIBsection patch
	m_DIBbits = NULL;
	m_freemainbuff = FALSE;
	m_formatmunged = FALSE;
	m_mainbuff = NULL;
	m_backbuff = NULL;

	m_clipboard_active = FALSE;
	m_hooks_active = FALSE;
	m_hooks_may_change = FALSE;
	m_lpAlternateDevMode = NULL;
	m_copyrect_set = FALSE;

	m_videodriver = NULL;

	m_timer_blank_screen = 0;
}

vncDesktop::~vncDesktop()
{

	// If we created a thread then here we delete it
	// The thread itself does most of the cleanup
	if(m_thread != NULL)
	{
		// Post a close message to quit our message handler thread
		PostMessage(Window(), WM_QUIT, 0, 0);

		// Join with the desktop handler thread
		void *returnval;
		m_thread->join(&returnval);
		m_thread = NULL;
	}

	// Let's call Shutdown just in case something went wrong...
	Shutdown();
	_ASSERTE(!m_lpAlternateDevMode);
}

// Routine to startup and install all the hooks and stuff
BOOL
vncDesktop::Startup()
{
	// Currently, we just check whether we're in the console session, and
	//   fail if not
	if (!inConsoleSession()) {
		return FALSE;
	}

	// Configure the display for optimal VNC performance.
	SetupDisplayForConnection();

	// Initialise the Desktop object
	if (!InitDesktop())
		return FALSE;

	if (InitVideoDriver())
	{
// this isn't really necessary
//		InvalidateRect(NULL,NULL,TRUE);
	}

	if (!InitBitmap())
		return FALSE;

	if (!ThunkBitmapInfo())
		return FALSE;

	if (!SetPixFormat())
		return FALSE;

	if (!CreateBuffers())
		return FALSE;

	if (!SetPixShifts())
		return FALSE;

	if (!SetPalette())
		return FALSE;

	if (!InitWindow())
		return FALSE;

	// Add the system hook
	//ActivateHooks();
	m_server->PollFullScreen(TRUE);
	m_hooks_may_change = true;

#ifndef HORIZONLIVE
	// Start up the keyboard and mouse filters
	//SetKeyboardFilterHook(m_server->LocalInputsDisabled());
	//SetMouseFilterHook(m_server->LocalInputsDisabled());
#endif

	// Start up the keyboard and mouse hooks  for 
	// local event priority over remote impl.
	if (m_server->LocalInputPriority())
		SetLocalInputPriorityHook(true);

	// Start a timer to handle Polling Mode.  The timer will cause
	// an "idle" event, which is necessary if Polling Mode is being used,
	// to cause TriggerUpdate to be called.
	SetPollingFlag(FALSE);
	SetPollingTimer();

	// If necessary, start a separate timer to preserve the diplay turned off.
	UpdateBlankScreenTimer();

	// Get hold of the WindowPos atom!
	if ((VNC_WINDOWPOS_ATOM = GlobalAddAtom(VNC_WINDOWPOS_ATOMNAME)) == 0) {

		return FALSE;
	}

// this member must be initialized: we cant assume the absence
// of clients when desktop is created.
	m_cursorpos.left = 0;
	m_cursorpos.top = 0;
	m_cursorpos.right = 0;
	m_cursorpos.bottom = 0;

	// Everything is ok, so return TRUE
	return TRUE;
}

// Routine to shutdown all the hooks and stuff
BOOL vncDesktop::Shutdown()
{
	// If we created timers then kill them
	if (m_timer_polling)
	{
		KillTimer(Window(), TIMER_POLL);
		m_timer_polling = 0;
	}
	if (m_timer_blank_screen)
	{
		KillTimer(Window(), TIMER_BLANK_SCREEN);
		m_timer_blank_screen = 0;
	}

	// If we created a window then kill it and the hooks
	if (m_hwnd != NULL)
	{	
		//Remove the system hooks
		//Unset keyboard and mouse hooks
		SetLocalInputPriorityHook(false);
		m_hooks_may_change = false;
		ShutdownHooks();

#ifndef HORIZONLIVE
		// Stop the keyboard and mouse filters
		//SetKeyboardFilterHook(false);
		//SetMouseFilterHook(false);
#endif
		// The window is being closed - remove it from the viewer list
		ChangeClipboardChain(m_hwnd, m_hnextviewer);

		// Close the hook window
		DestroyWindow(m_hwnd);
		m_hwnd = NULL;
		m_hnextviewer = NULL;
	}

	// Now free all the bitmap stuff
	if (m_hrootdc != NULL)
	{
		// Release our device context
		ReleaseDC(NULL, m_hrootdc);
		m_hrootdc = NULL;
	}
	if (m_hmemdc != NULL)
	{
		// Release our device context
		DeleteDC(m_hmemdc);
		m_hmemdc = NULL;
	}
	if (m_membitmap != NULL)
	{
		// Release the custom bitmap, if any
		DeleteObject(m_membitmap);
		m_membitmap = NULL;
	}

	// Free back buffer
	if (m_backbuff != NULL)
	{
		delete [] m_backbuff;
		m_backbuff = NULL;
	}

	if (m_freemainbuff)
	{
		// Slow blits were enabled - free the slow blit buffer
		if (m_mainbuff != NULL)
		{
			delete [] m_mainbuff;
			m_mainbuff = NULL;
		}
	}

	// Free the WindowPos atom!
	if (VNC_WINDOWPOS_ATOM != NULL)
	{
		GlobalDeleteAtom(VNC_WINDOWPOS_ATOM);
	}

	ShutdownVideoDriver();

	return TRUE;
}

// Routines to set/unset hooks via VNCHooks.dll

void
vncDesktop::ActivateHooks()
{
	BOOL enable = !(m_server->DontSetHooks() && m_server->PollFullScreen());
	if (enable && !m_hooks_active) {
		//m_hooks_active = SetHook(m_hwnd,
		//						 RFB_SCREEN_UPDATE,
		//						 RFB_COPYRECT_UPDATE,
		//						 RFB_MOUSE_UPDATE);
		if (!m_hooks_active) {

			// Switch on full screen polling, so they can see something, at least...
			m_server->PollFullScreen(TRUE);
		}
	} else if (!enable) {
		ShutdownHooks();
	}
}

void
vncDesktop::ShutdownHooks()
{
	//if (m_hooks_active)
	//	m_hooks_active = !UnSetHook(m_hwnd);
}

void
vncDesktop::TryActivateHooks()
{
	if (m_hooks_may_change)
		ActivateHooks();
}

// Routine to ensure we're on the correct NT desktop

BOOL
vncDesktop::InitDesktop()
{
	if (vncService::InputDesktopSelected())
		return TRUE;

	// Ask for the current input desktop
	return vncService::SelectDesktop(NULL);
}

// Routine used to close the screen saver, if it's active...

BOOL CALLBACK
KillScreenSaverFunc(HWND hwnd, LPARAM lParam)
{
	char buffer[256];

	// - ONLY try to close Screen-saver windows!!!
	if ((GetClassName(hwnd, buffer, 256) != 0) &&
		(strcmp(buffer, "WindowsScreenSaverClass") == 0))
		PostMessage(hwnd, WM_CLOSE, 0, 0);
	return TRUE;
}

void
vncDesktop::KillScreenSaver()
{
	OSVERSIONINFO osversioninfo;
	osversioninfo.dwOSVersionInfoSize = sizeof(osversioninfo);

	// Get the current OS version
	if (!GetVersionEx(&osversioninfo))
		return;


	// How to kill the screen saver depends on the OS
	switch (osversioninfo.dwPlatformId)
	{
	case VER_PLATFORM_WIN32_WINDOWS:
		{
			// Windows 95

			// Fidn the ScreenSaverClass window
			HWND hsswnd = FindWindow ("WindowsScreenSaverClass", NULL);
			if (hsswnd != NULL)
				PostMessage(hsswnd, WM_CLOSE, 0, 0); 
			break;
		} 
	case VER_PLATFORM_WIN32_NT:
		{
			// Windows NT

			// Find the screensaver desktop
			HDESK hDesk = OpenDesktop(
				"Screen-saver",
				0,
				FALSE,
				DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS
				);
			if (hDesk != NULL)
			{
				// Close all windows on the screen saver desktop
				EnumDesktopWindows(hDesk, (WNDENUMPROC) &KillScreenSaverFunc, 0);
				CloseDesktop(hDesk);
				// Pause long enough for the screen-saver to close
				//Sleep(2000);
				// Reset the screen saver so it can run again
				SystemParametersInfo(SPI_SETSCREENSAVEACTIVE, TRUE, 0, SPIF_SENDWININICHANGE); 
			}
			break;
		}
	}
}

void vncDesktop::ChangeResNow()
{
// IMPORTANT: Screen mode alteration may only take place on a single-mon system.
	if (IsMultiMonDesktop())
	{
		return;
	}

	BOOL settingsUpdated = false;
	int i = 0;

	_ASSERTE(!m_lpAlternateDevMode);
	m_lpAlternateDevMode = new DEVMODE; // *** create an instance of DEVMODE - Jeremy Peaks
	if (!m_lpAlternateDevMode)
	{
		return;
	}

	// *** WBB - Obtain the current display settings.
	// only on unimon
	if (! EnumDisplaySettings(0, ENUM_CURRENT_SETTINGS, m_lpAlternateDevMode))
	{
		delete m_lpAlternateDevMode;
		m_lpAlternateDevMode = NULL;
		return;

	}

	origPelsWidth = m_lpAlternateDevMode->dmPelsWidth; // *** sets the original resolution for use later
	origPelsHeight = m_lpAlternateDevMode->dmPelsHeight; // *** - Jeremy Peaks

	// *** Open the registry key for resolution settings
	/*HKEY checkdetails = 0;
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
				WINVNC_REGISTRY_KEY,
				0,
				KEY_READ,
				&checkdetails);
	if (checkdetails)
	{
		int slen=MAX_REG_ENTRY_LEN;
		int valType;
		char inouttext[MAX_REG_ENTRY_LEN];

		memset(inouttext, 0, MAX_REG_ENTRY_LEN);
		
		// *** Get the registry values for resolution change - Jeremy Peaks
		RegQueryValueEx(checkdetails,
			"ResWidth",
			NULL,
			(LPDWORD) &valType,
			(LPBYTE) &inouttext,
			(LPDWORD) &slen);

		
		if ((valType == REG_SZ) &&
			atol(inouttext)) { // *** if width is 0, then this isn't a valid resolution, so do nothing - Jeremy Peaks
			m_lpAlternateDevMode->dmPelsWidth = atol(inouttext);

			memset(inouttext, 0, MAX_REG_ENTRY_LEN);

			RegQueryValueEx(checkdetails,
				"ResHeight",
				NULL,
				(LPDWORD) &valType,
				(LPBYTE) &inouttext,
				(LPDWORD) &slen);
			
			m_lpAlternateDevMode->dmPelsHeight = atol(inouttext);
			if ((valType == REG_SZ ) &&
				(m_lpAlternateDevMode->dmPelsHeight > 0)) {

				// *** make res change - Jeremy Peaks
				// testing: predefined Width/Height may become incompatible
				// with new clrdepth/timings
				long resultOfResChange = ChangeDisplaySettings(m_lpAlternateDevMode, CDS_TEST);
				if (resultOfResChange == DISP_CHANGE_SUCCESSFUL) {
					ChangeDisplaySettings(m_lpAlternateDevMode, CDS_UPDATEREGISTRY);
					settingsUpdated = true;
				}
			} 
		}

		RegCloseKey(checkdetails);
	}*/

	if (! settingsUpdated)
	{
// Did not change the resolution.
		delete m_lpAlternateDevMode;
		m_lpAlternateDevMode = NULL;
	}
}

void
vncDesktop::SetupDisplayForConnection()
{
	KillScreenSaver();

	ChangeResNow(); // *** - Jeremy Peaks
}

void
vncDesktop::ResetDisplayToNormal()
{
	if (m_lpAlternateDevMode != NULL)
	{
		// *** In case the resolution was changed, revert to original settings now
		m_lpAlternateDevMode->dmPelsWidth = origPelsWidth;
		m_lpAlternateDevMode->dmPelsHeight = origPelsHeight;

		long resultOfResChange = ChangeDisplaySettings(m_lpAlternateDevMode, CDS_TEST);
		if (resultOfResChange == DISP_CHANGE_SUCCESSFUL)
			ChangeDisplaySettings(m_lpAlternateDevMode, CDS_UPDATEREGISTRY);

		delete m_lpAlternateDevMode;
		m_lpAlternateDevMode = NULL;
	}
}

RECT vncDesktop::GetSourceRect()
{
	if (m_server->WindowShared())
	{
		RECT wrect;
		GetWindowRect(m_server->GetWindowShared(), &wrect);
		return wrect;
	}
	else if (m_server->ScreenAreaShared())
	{
		return m_server->GetScreenAreaRect();
	}
	else if (m_server->PrimaryDisplayOnlyShared())
	{
		RECT pdr = { 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN) };
		return pdr;
	}
	else
	{
#ifdef _DEBUG
		RECT rd;
		_ASSERTE(GetSourceDisplayRect(rd));
		_ASSERTE(EqualRect(&rd, &m_bmrect));
#endif
		return m_bmrect;
	}
}

RECT	GetScreenRect()
{
	RECT screenrect;
	if (IsWinVerOrHigher(4, 10))
	{
		screenrect.left		= GetSystemMetrics(SM_XVIRTUALSCREEN);
		screenrect.top		= GetSystemMetrics(SM_YVIRTUALSCREEN);
		screenrect.right	= screenrect.left + GetSystemMetrics(SM_CXVIRTUALSCREEN);
		screenrect.bottom	= screenrect.top + GetSystemMetrics(SM_CYVIRTUALSCREEN);
	}
	else
	{
		screenrect.left = 0;
		screenrect.top = 0;
		screenrect.right = GetSystemMetrics(SM_CXSCREEN);
		screenrect.bottom = GetSystemMetrics(SM_CYSCREEN);
	}
	return screenrect;
}

BOOL vncDesktop::GetSourceDisplayRect(RECT &rdisp_rect)
{
	if (!m_hrootdc)
		m_hrootdc = ::GetDC(NULL);
	if (!m_hrootdc)
	{
		return FALSE;
	}

// TODO: refactor it
	rdisp_rect = GetScreenRect();
	return TRUE;
}

BOOL vncDesktop::InitBitmap()
{
// IMPORTANT: here an optimization may be implemented
// when only a fixed rect is shared.
// then m_bmrect should be set to that rect.
	if (!GetSourceDisplayRect(m_bmrect))
	{
		return FALSE;
	}


	// Create a compatible memory DC
	m_hmemdc = CreateCompatibleDC(m_hrootdc);
	if (m_hmemdc == NULL) {

		return FALSE;
	}

	// Check that the device capabilities are ok
	if ((GetDeviceCaps(m_hrootdc, RASTERCAPS) & RC_BITBLT) == 0)
	{

		return FALSE;
	}
	if ((GetDeviceCaps(m_hmemdc, RASTERCAPS) & RC_DI_BITMAP) == 0)
	{

		return FALSE;
	}

	// Create the bitmap to be compatible with the ROOT DC!!!
	m_membitmap = CreateCompatibleBitmap(
		m_hrootdc,
		m_bmrect.right - m_bmrect.left,
		m_bmrect.bottom - m_bmrect.top);
	if (m_membitmap == NULL)
	{
		return FALSE;
	}

	// Get the bitmap's format and colour details
	int result;
	m_bminfo.bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	m_bminfo.bmi.bmiHeader.biBitCount = 0;
	result = ::GetDIBits(m_hmemdc, m_membitmap, 0, 1, NULL, &m_bminfo.bmi, DIB_RGB_COLORS);
	if (result == 0) {
		return FALSE;
	}
	result = ::GetDIBits(m_hmemdc, m_membitmap, 0, 1, NULL, &m_bminfo.bmi, DIB_RGB_COLORS);
	if (result == 0) {
		return FALSE;
	}

	if (GetDeviceCaps(m_hmemdc, PLANES) != 1)
	{

		return FALSE;
	}

	// Henceforth we want to use a top-down scanning representation
	m_bminfo.bmi.bmiHeader.biHeight = - abs(m_bminfo.bmi.bmiHeader.biHeight);

	// Is the bitmap palette-based or truecolour?
	m_bminfo.truecolour = (GetDeviceCaps(m_hmemdc, RASTERCAPS) & RC_PALETTE) == 0;

	return TRUE;
}


BOOL
vncDesktop::ThunkBitmapInfo()
{
	// If we leave the pixel format intact, the blits can be optimised (Will Dean's patch)
	m_formatmunged = FALSE;

	// HACK ***.  Optimised blits don't work with palette-based displays, yet
	if (!m_bminfo.truecolour) {
		m_formatmunged = TRUE;
	}

	// Attempt to force the actual format into one we can handle
	// We can handle 8-bit-palette and 16/32-bit-truecolour modes
	switch (m_bminfo.bmi.bmiHeader.biBitCount)
	{
	case 1:
	case 4:

		
		// Correct the BITMAPINFO header to the format we actually want
		m_bminfo.bmi.bmiHeader.biClrUsed = 0;
		m_bminfo.bmi.bmiHeader.biPlanes = 1;
		m_bminfo.bmi.bmiHeader.biCompression = BI_RGB;
		m_bminfo.bmi.bmiHeader.biBitCount = 8;
		m_bminfo.bmi.bmiHeader.biSizeImage =
			abs((m_bminfo.bmi.bmiHeader.biWidth *
				m_bminfo.bmi.bmiHeader.biHeight *
				m_bminfo.bmi.bmiHeader.biBitCount)/ 8);
		m_bminfo.bmi.bmiHeader.biClrImportant = 0;
		m_bminfo.truecolour = FALSE;

		// Display format is non-VNC compatible - use the slow blit method
		m_formatmunged = TRUE;
		break;	
	case 24:
		// Update the bitmapinfo header
		m_bminfo.bmi.bmiHeader.biBitCount = 32;
		m_bminfo.bmi.bmiHeader.biPlanes = 1;
		m_bminfo.bmi.bmiHeader.biCompression = BI_RGB;
		m_bminfo.bmi.bmiHeader.biSizeImage =
			abs((m_bminfo.bmi.bmiHeader.biWidth *
				m_bminfo.bmi.bmiHeader.biHeight *
				m_bminfo.bmi.bmiHeader.biBitCount)/ 8);
		// Display format is non-VNC compatible - use the slow blit method
		m_formatmunged = TRUE;
		break;
	}

	return TRUE;
}

BOOL
vncDesktop::SetPixFormat()
{
	// Examine the bitmapinfo structure to obtain the current pixel format
	m_scrinfo.format.trueColour = m_bminfo.truecolour;
	m_scrinfo.format.bigEndian = 0;

	// Set up the native buffer width, height and format
	m_scrinfo.framebufferWidth = (CARD16) (m_bmrect.right - m_bmrect.left);		// Swap endian before actually sending
	m_scrinfo.framebufferHeight = (CARD16) (m_bmrect.bottom - m_bmrect.top);	// Swap endian before actually sending
	m_scrinfo.format.bitsPerPixel = (CARD8) m_bminfo.bmi.bmiHeader.biBitCount;
	m_scrinfo.format.depth        = (CARD8) m_bminfo.bmi.bmiHeader.biBitCount;

	
	// Calculate the number of bytes per row
	m_bytesPerRow = m_scrinfo.framebufferWidth * m_scrinfo.format.bitsPerPixel / 8;

	return TRUE;
}

BOOL
vncDesktop::SetPixShifts()
{
	// Sort out the colour shifts, etc.
	DWORD redMask=0, blueMask=0, greenMask = 0;

	switch (m_bminfo.bmi.bmiHeader.biBitCount)
	{
	case 16:
		if (m_videodriver&& m_videodriver->IsDirectAccessInEffect())
		{
// IMPORTANT: Mirage colormask is always 565
			redMask = 0xf800;
			greenMask = 0x07e0;
			blueMask = 0x001f;
		}
		else if (m_bminfo.bmi.bmiHeader.biCompression == BI_RGB)
		{
		// Standard 16-bit display
		// each word single pixel 5-5-5
			redMask = 0x7c00; greenMask = 0x03e0; blueMask = 0x001f;
		}
		else
		{
			if (m_bminfo.bmi.bmiHeader.biCompression == BI_BITFIELDS)
			{
				redMask =   *(DWORD *) &m_bminfo.bmi.bmiColors[0];
				greenMask = *(DWORD *) &m_bminfo.bmi.bmiColors[1];
				blueMask =  *(DWORD *) &m_bminfo.bmi.bmiColors[2];
			}
		}
		break;

	case 32:
		// Standard 24/32 bit displays
		if (m_bminfo.bmi.bmiHeader.biCompression == BI_RGB ||
			m_videodriver && m_videodriver->IsDirectAccessInEffect())
		{
			redMask = 0xff0000;
			greenMask = 0xff00;
			blueMask = 0x00ff;

			// The real color depth is 24 bits in this case. If the depth
			// is set to 32, the Tight encoder shows worse performance.
			m_scrinfo.format.depth = 24;
		}
		else
		{
			if (m_bminfo.bmi.bmiHeader.biCompression == BI_BITFIELDS)
			{
				redMask =   *(DWORD *) &m_bminfo.bmi.bmiColors[0];
				greenMask = *(DWORD *) &m_bminfo.bmi.bmiColors[1];
				blueMask =  *(DWORD *) &m_bminfo.bmi.bmiColors[2];
			}
		}
		break;

	default:
		// Other pixel formats are only valid if they're palette-based
		if (m_bminfo.truecolour)
		{

			return FALSE;
		}

		return TRUE;
	}

	// Convert the data we just retrieved
	MaskToMaxAndShift(redMask, m_scrinfo.format.redMax, m_scrinfo.format.redShift);
	MaskToMaxAndShift(greenMask, m_scrinfo.format.greenMax, m_scrinfo.format.greenShift);
	MaskToMaxAndShift(blueMask, m_scrinfo.format.blueMax, m_scrinfo.format.blueShift);


	return TRUE;
}

BOOL
vncDesktop::SetPalette()
{
	// Lock the current display palette into the memory DC we're holding
	// *** CHECK THIS FOR LEAKS!
	if (!m_bminfo.truecolour)
	{
		LOGPALETTE *palette;
		UINT size = sizeof(LOGPALETTE) + (sizeof(PALETTEENTRY) * 256);

		palette = (LOGPALETTE *) new char[size];
		if (palette == NULL) {

			return FALSE;
		}

		// Initialise the structure
		palette->palVersion = 0x300;
		palette->palNumEntries = 256;

		// Get the system colours
		if (GetSystemPaletteEntries(m_hrootdc, 0, 256, palette->palPalEntry) == 0)
		{

			delete [] palette;
			return FALSE;
		}

		// Create a palette from those
		HPALETTE pal = CreatePalette(palette);
		if (pal == NULL)
		{

			delete [] palette;
			return FALSE;
		}

		// Select the palette into our memory DC
		HPALETTE oldpalette = SelectPalette(m_hmemdc, pal, FALSE);
		if (oldpalette == NULL)
		{

			delete [] palette;
			DeleteObject(pal);
			return FALSE;
		}

		// Worked, so realise the palette
		RealizePalette(m_hmemdc);

		// It worked!
		delete [] palette;
		DeleteObject(oldpalette);

		return TRUE;
	}

	// Not a palette based local screen - forget it!

	return TRUE;
}

LRESULT CALLBACK DesktopWndProc(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam);

ATOM m_wndClass = 0;

BOOL vncDesktop::InitWindow()
{
	if (m_wndClass == 0) {
		// Create the window class
		WNDCLASSEX wndclass;

		wndclass.cbSize			= sizeof(wndclass);
		wndclass.style			= 0;
		wndclass.lpfnWndProc	= &DesktopWndProc;
		wndclass.cbClsExtra		= 0;
		wndclass.cbWndExtra		= 0;
		wndclass.hInstance		= hAppInstance;
		wndclass.hIcon			= NULL;
		wndclass.hCursor		= NULL;
		wndclass.hbrBackground	= (HBRUSH) GetStockObject(WHITE_BRUSH);
		wndclass.lpszMenuName	= (const char *) NULL;
		wndclass.lpszClassName	= szDesktopSink;
		wndclass.hIconSm		= NULL;

		// Register it
		m_wndClass = RegisterClassEx(&wndclass);
	}

	// And create a window
	m_hwnd = CreateWindow(szDesktopSink,
				"WinVNC",
				WS_OVERLAPPEDWINDOW,
				CW_USEDEFAULT,
				CW_USEDEFAULT,
				400, 200,
				NULL,
				NULL,
				hAppInstance,
				NULL);

	if (m_hwnd == NULL) {

		return FALSE;
	}

	// Set the "this" pointer for the window
	SetWindowLong(m_hwnd, -21, (long)this); // #define GWL_USERDATA        (-21)

	// Enable clipboard hooking
	m_hnextviewer = SetClipboardViewer(m_hwnd);

	return TRUE;
}

BOOL
vncDesktop::CreateBuffers()
{

	// Create a new DIB section ***
	HBITMAP tempbitmap = NULL;
	if (!m_formatmunged)
	{
		tempbitmap = CreateDIBSection(
			m_hmemdc,
			&m_bminfo.bmi,
			DIB_RGB_COLORS,
			&m_DIBbits,
			NULL,
			0);
	}

	m_freemainbuff = false;

// NOTE m_mainbuff and m_backbuff allocation can not be supressed
// even with direct access mirror surface view

	if (tempbitmap == NULL)
	{
		m_DIBbits = NULL;
		// create our own buffer to copy blits through
		if ((m_mainbuff = new BYTE [ScreenBuffSize()]) == NULL) {
				return FALSE;
		}
		m_freemainbuff = true;
		if ((m_backbuff = new BYTE [ScreenBuffSize()]) == NULL) {
			return FALSE;
		}
		return TRUE;
	}
	
	// Create our own buffer to copy blits through
	if ((m_backbuff = new BYTE [ScreenBuffSize()]) == NULL) {
		if (tempbitmap!= NULL)
			DeleteObject(tempbitmap);
		return FALSE;
	}

	// Delete the old memory bitmap
	if (m_membitmap != NULL) {
		DeleteObject(m_membitmap);
		m_membitmap = NULL;
	}

	// Replace old membitmap with DIB section
	m_membitmap = tempbitmap;
	m_mainbuff = (BYTE *)m_DIBbits;

	return TRUE;
}

BOOL
vncDesktop::Init(vncServer *server)
{

	// Save the server pointer
	m_server = server;

	// Load in the arrow cursor
	m_hdefcursor = LoadCursor(NULL, IDC_ARROW);
	m_hcursor = m_hdefcursor;

	// Spawn a thread to handle that window's message queue
	vncDesktopThread *thread = new vncDesktopThread;
	if (thread == NULL)
		return FALSE;
	m_thread = thread;
	return thread->Init(this, m_server);
}

void
vncDesktop::RequestUpdate()
{
	PostMessage(m_hwnd, WM_TIMER, TIMER_POLL, 0);
}

int
vncDesktop::ScreenBuffSize()
{
	return m_scrinfo.format.bitsPerPixel/8 *
		m_scrinfo.framebufferWidth *
		m_scrinfo.framebufferHeight;
}

void
vncDesktop::FillDisplayInfo(rfbServerInitMsg *scrinfo)
{
	memcpy(scrinfo, &m_scrinfo, sz_rfbServerInitMsg);
}

// Function to capture an area of the screen immediately prior to sending
// an update.

void vncDesktop::CaptureScreen(RECT &UpdateArea, BYTE *scrBuff)
{
// ASSUME rect related to virtual desktop
	if (m_videodriver && m_videodriver->IsDirectAccessInEffect())
			CaptureScreenFromMirage(UpdateArea, scrBuff);
	else	CaptureScreenFromAdapterGeneral(UpdateArea, scrBuff);
}

void vncDesktop::CaptureScreenFromAdapterGeneral(RECT rect, BYTE *scrBuff)
{
// ASSUME rect related to virtual desktop
	// Protect the memory bitmap
	omni_mutex_lock l(m_bitbltlock);

	// Finish drawing anything in this thread 
	// Wish we could do this for the whole system - maybe we should
	// do something with LockWindowUpdate here.
	GdiFlush();

	// Select the memory bitmap into the memory DC
	HBITMAP oldbitmap;
	if ((oldbitmap = (HBITMAP) SelectObject(m_hmemdc, m_membitmap)) == NULL)
		return;

	// Capture screen into bitmap
	BOOL blitok = BitBlt(
		m_hmemdc,
// source in m_hrootdc is relative to a virtual desktop,
// whereas dst coordinates of m_hmemdc are relative to its top-left corner (0, 0)
		rect.left - m_bmrect.left,
		rect.top - m_bmrect.top,
		rect.right - rect.left,
		rect.bottom - rect.top,
		m_hrootdc,
		rect.left, rect.top,
		SRCCOPY);

	// Select the old bitmap back into the memory DC
	SelectObject(m_hmemdc, oldbitmap);
	
	if (blitok)
	{
	// Copy the new data to the screen buffer (CopyToBuffer optimises this if possible)
		CopyToBuffer(rect, scrBuff);
	}

}

void vncDesktop::CaptureScreenFromMirage(RECT UpdateArea, BYTE *scrBuff)
{
// ASSUME rect related to virtual desktop
	_ASSERTE(m_videodriver);
	omni_mutex_lock l(m_bitbltlock);
	CopyToBuffer(UpdateArea, scrBuff, m_videodriver->GetScreenView());
}

void	vncDesktop::CaptureMouseRect()
{
	POINT CursorPos;
	ICONINFO IconInfo;

	// If the mouse cursor handle is invalid then forget it
	if (m_hcursor == NULL)
		return;

	// Get the cursor position
	if (!GetCursorPos(&CursorPos))
		return;

	// Translate position for hotspot
	if (GetIconInfo(m_hcursor, &IconInfo))
	{
		CursorPos.x -= ((int) IconInfo.xHotspot);
		CursorPos.y -= ((int) IconInfo.yHotspot);

		if (IconInfo.hbmMask != NULL)
			DeleteObject(IconInfo.hbmMask);
		if (IconInfo.hbmColor != NULL)
			DeleteObject(IconInfo.hbmColor);
	}

	// Save the bounding rectangle
	m_cursorpos.left = CursorPos.x;
	m_cursorpos.top = CursorPos.y;
	m_cursorpos.right = CursorPos.x + GetSystemMetrics(SM_CXCURSOR);
	m_cursorpos.bottom = CursorPos.y + GetSystemMetrics(SM_CYCURSOR);
}

// Add the mouse pointer to the buffer
void vncDesktop::CaptureMouse(BYTE *scrBuff, UINT scrBuffSize)
{
	// Protect the memory bitmap
	omni_mutex_lock l(m_bitbltlock);

	CaptureMouseRect();

	// Select the memory bitmap into the memory DC
	HBITMAP oldbitmap;
	if ((oldbitmap = (HBITMAP) SelectObject(m_hmemdc, m_membitmap)) == NULL)
		return;

	// Draw the cursor
	DrawIconEx(
		m_hmemdc,									// handle to device context 
		m_cursorpos.left - m_bmrect.left,
		m_cursorpos.top - m_bmrect.top,
		m_hcursor,									// handle to icon to draw 
		0,0,										// width of the icon 
		0,											// index of frame in animated cursor 
		NULL,										// handle to background brush 
		DI_NORMAL									// icon-drawing flags 
		);

	// Select the old bitmap back into the memory DC
	SelectObject(m_hmemdc, oldbitmap);

	// Clip the bounding rect to the screen
	RECT screen = m_server->GetSharedRect();
	// Copy the mouse cursor into the screen buffer, if any of it is visible
	if (IntersectRect(&m_cursorpos, &m_cursorpos, &screen))
		CopyToBuffer(m_cursorpos, scrBuff);
}

// Obtain cursor image data in server's local format.
// The length of databuf[] should be at least (width * height * 4).
BOOL
vncDesktop::GetRichCursorData(BYTE *databuf, HCURSOR hcursor, int width, int height)
{
	// Protect the memory bitmap (is it really necessary here?)
	omni_mutex_lock l(m_bitbltlock);

	// Create bitmap, select it into memory DC
	HBITMAP membitmap = CreateCompatibleBitmap(m_hrootdc, width, height);
	if (membitmap == NULL) {
		return FALSE;
	}
	HBITMAP oldbitmap = (HBITMAP) SelectObject(m_hmemdc, membitmap);
	if (oldbitmap == NULL) {
		DeleteObject(membitmap);
		return FALSE;
	}

	// Draw the cursor
	DrawIconEx(m_hmemdc, 0, 0, hcursor, 0, 0, 0, NULL, DI_IMAGE);
	SelectObject(m_hmemdc, oldbitmap);

	// Prepare BITMAPINFO structure (copy most m_bminfo fields)
	BITMAPINFO *bmi = (BITMAPINFO *)calloc(1, sizeof(BITMAPINFO) + 256 * sizeof(RGBQUAD));
	memcpy(bmi, &m_bminfo.bmi, sizeof(BITMAPINFO) + 256 * sizeof(RGBQUAD));
	bmi->bmiHeader.biWidth = width;
	bmi->bmiHeader.biHeight = -height;

	// Clear data buffer and extract RGB data
	memset(databuf, 0x00, width * height * 4);
	int lines = GetDIBits(m_hmemdc, membitmap, 0, height, databuf, bmi, DIB_RGB_COLORS);

	// Cleanup
	free(bmi);
	DeleteObject(membitmap);

	return (lines != 0);
}

// Return the current mouse pointer position
RECT
vncDesktop::MouseRect()
{
	return m_cursorpos;
}

void vncDesktop::SetCursor(HCURSOR cursor)
{
	if (cursor == NULL)
		m_hcursor = m_hdefcursor;
	else
		m_hcursor = cursor;
}

//
// Convert text from Unix (LF only) format to CR+LF.
// NOTE: The size of dst[] buffer must be at least (strlen(src) * 2 + 1).
//

void
vncDesktop::ConvertClipText(char *dst, const char *src)
{
	const char *ptr0 = src;
	const char *ptr1;
#ifdef __x64__
	__int64 dst_pos = 0;
#else
	int dst_pos = 0;
#endif

	while ((ptr1 = strchr(ptr0, '\n')) != NULL) {
		// Copy the string before the LF
		if (ptr1 != ptr0) {
			memcpy(&dst[dst_pos], ptr0, ptr1 - ptr0);
			dst_pos += ptr1 - ptr0;
		}
		// Don't insert CR if there is one already
		if (ptr1 == ptr0 || *(ptr1 - 1) != '\r') {
			dst[dst_pos++] = '\r';
		}
		// Append LF
		dst[dst_pos++] = '\n';
		// Next position in the source text
		ptr0 = ptr1 + 1;
	}
	// Copy the last string with no LF, but with '\0'
	memcpy(&dst[dst_pos], ptr0, &src[strlen(src)] - ptr0 + 1);
}

//
// Manipulation of the clipboard
//

void
vncDesktop::SetClipText(LPSTR text)
{
	// Open the system clipboard
	if (OpenClipboard(m_hwnd))
	{
		// Empty it
		if (EmptyClipboard())
		{
			HANDLE hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE,
									  strlen(text) * 2 + 1);

			if (hMem != NULL)
			{
				LPSTR pMem = (char*)GlobalLock(hMem);

				// Get the data (with line endings converted to CR+LF)
				ConvertClipText(pMem, text);

				// Tell the clipboard
				GlobalUnlock(hMem);
				SetClipboardData(CF_TEXT, hMem);
			}
		}
	}

	// Now close it
	CloseClipboard();
}

// INTERNAL METHODS

inline void
vncDesktop::MaskToMaxAndShift(DWORD mask, CARD16 &max, CARD8 &shift)
{
	for (shift = 0; (mask & 1) == 0; shift++)
		mask >>= 1;
	max = (CARD16) mask;
}

// Copy data from the memory bitmap into a buffer
void vncDesktop::CopyToBuffer(RECT rect, BYTE *destbuff)
{
	// Are we being asked to blit from the DIBsection to itself?
	if (destbuff == m_DIBbits)
	{
		// Yes.  Ignore the request!
		return;
	}

	// Protect the memory bitmap
	omni_mutex_lock l(m_bitbltlock);

	const int crect_re_vd_left = rect.left - m_bmrect.left;
	const int crect_re_vd_top = rect.top - m_bmrect.top;
	_ASSERTE(crect_re_vd_left >= 0);
	_ASSERTE(crect_re_vd_top >= 0);

	// Calculate the scanline-ordered y position to copy from
// NB: m_membitmap is bottom2top
	const int y_inv_re_vd = m_bmrect.bottom - m_bmrect.top - rect.bottom;
	_ASSERTE(y_inv_re_vd >= 0);

	// Calculate where in the output buffer to put the data
	BYTE * destbuffpos = destbuff + (m_bytesPerRow * crect_re_vd_top);

	// Set the number of bytes for GetDIBits to actually write
	// NOTE : GetDIBits pads the destination buffer if biSizeImage < no. of bytes required
	m_bminfo.bmi.bmiHeader.biSizeImage = (rect.bottom-rect.top) * m_bytesPerRow;

	// Get the actual bits from the bitmap into the bit buffer
	// If fast (DIBsection) blits are disabled then use the old GetDIBits technique
	if (m_DIBbits == NULL)
	{
		if (GetDIBits(
			m_hmemdc,
			m_membitmap,
			y_inv_re_vd,
			rect.bottom - rect.top,
			destbuffpos,
			&m_bminfo.bmi,
			DIB_RGB_COLORS) == 0)
		{
#ifdef _MSC_VER
			_RPT1(_CRT_WARN, "vncDesktop : [1] GetDIBits failed! %d\n", GetLastError());
			_RPT3(_CRT_WARN, "vncDesktop : thread = %d, DC = %d, bitmap = %d\n", omni_thread::self(), m_hmemdc, m_membitmap);
			_RPT2(_CRT_WARN, "vncDesktop : y = %d, height = %d\n", y_inv_re_vd, (rect.bottom-rect.top));
#endif
		}
	}
	else
	{
		// Fast blits are enabled.  [I have a sneaking suspicion this will never get used, unless
		// something weird goes wrong in the code.  It's here to keep the function general, though!]

		const int bytesPerPixel = m_scrinfo.format.bitsPerPixel / 8;
		BYTE *srcbuffpos = (BYTE*)m_DIBbits;

		srcbuffpos += (m_bytesPerRow * crect_re_vd_top) + (bytesPerPixel * crect_re_vd_left);
		destbuffpos += bytesPerPixel * crect_re_vd_left;

		const int widthBytes = (rect.right - rect.left) * bytesPerPixel;

		for (int y = rect.top; y < rect.bottom; y++)
		{
			memcpy(destbuffpos, srcbuffpos, widthBytes);
			srcbuffpos += m_bytesPerRow;
			destbuffpos += m_bytesPerRow;
		}
	}
}

void vncDesktop::CopyToBuffer(RECT rect, BYTE *destbuff, const BYTE *srcbuffpos)
{
	const int crect_re_vd_left = rect.left - m_bmrect.left;
	const int crect_re_vd_top = rect.top - m_bmrect.top;
	_ASSERTE(crect_re_vd_left >= 0);
	_ASSERTE(crect_re_vd_top >= 0);

	const int bytesPerPixel = m_scrinfo.format.bitsPerPixel / 8;

	const int bmoffset = (m_bytesPerRow * crect_re_vd_top) + (bytesPerPixel * crect_re_vd_left);
	BYTE *destbuffpos = destbuff + bmoffset;
	srcbuffpos += bmoffset;

	const int widthBytes = (rect.right - rect.left) * bytesPerPixel;

	for (int y = rect.top; y < rect.bottom; y++)
	{
		memcpy(destbuffpos, srcbuffpos, widthBytes);
		srcbuffpos += m_bytesPerRow;
		destbuffpos += m_bytesPerRow;
	}
}

// Callback routine used internally to catch window movement...
BOOL CALLBACK
EnumWindowsFnCopyRect(HWND hwnd, LPARAM arg)
{

	//For excluding the popup windows
	if ((GetWindowLong( hwnd, GWL_STYLE) & WS_POPUP) ==0)
	{
	
		HANDLE prop = GetProp(hwnd, (LPCTSTR) MAKELONG(VNC_WINDOWPOS_ATOM, 0));
		if (prop != NULL) {
			
			if (IsWindowVisible(hwnd)) {
				
				RECT dest;
				POINT source;

				// Get the window rectangle
				if (GetWindowRect(hwnd, &dest)) {
					// Old position
					source.x = (SHORT) LOWORD(prop);
					source.y = (SHORT) HIWORD(prop);

					// Got the destination position.  Now send to clients!
					if ((source.x != dest.left) || (source.y != dest.top)) {
						// Update the property entry
						SHORT x = (SHORT) dest.left;
						SHORT y = (SHORT) dest.top;
						SetProp(hwnd,
							(LPCTSTR) MAKELONG(VNC_WINDOWPOS_ATOM, 0),
							(HANDLE) MAKELONG(x, y));

						// Store of the copyrect 
						((vncDesktop*)arg)->CopyRect(dest, source);
						
					}
				} else {
					RemoveProp(hwnd, (LPCTSTR) MAKELONG(VNC_WINDOWPOS_ATOM, 0));
				}
			} else {
				RemoveProp(hwnd, (LPCTSTR) MAKELONG(VNC_WINDOWPOS_ATOM, 0));
			}
		} else {
			// If the window has become visible then save its position!
			if (IsWindowVisible(hwnd)) {
				RECT dest;

				if (GetWindowRect(hwnd, &dest)) {
					SHORT x = (SHORT) dest.left;
					SHORT y = (SHORT) dest.top;
					SetProp(hwnd,
						(LPCTSTR) MAKELONG(VNC_WINDOWPOS_ATOM, 0),
						(HANDLE) MAKELONG(x, y));
				}
			}
		}
	}
	return TRUE;
}


void
vncDesktop::SetLocalInputDisableHook(BOOL enable)
{
	//SetKeyboardFilterHook(enable);
	//SetMouseFilterHook(enable);
}

void
vncDesktop::SetLocalInputPriorityHook(BOOL enable)
{
	if (vncService::IsWin95()) {
		//SetKeyboardPriorityHook(m_hwnd,enable,RFB_LOCAL_KEYBOARD);
		//SetMousePriorityHook(m_hwnd,enable,RFB_LOCAL_MOUSE);
	} else {
		//SetKeyboardPriorityLLHook(m_hwnd,enable,RFB_LOCAL_KEYBOARD);
		//SetMousePriorityLLHook(m_hwnd,enable,RFB_LOCAL_MOUSE);
	}

	if (!enable)
// FIXME: incremental semantics broken here;
// that's why we're compelled to consume extra unlocks
		m_server->BlockRemoteInput(false);
}

// Routine to find out which windows have moved
void
vncDesktop::CalcCopyRects()
{
	// Enumerate all the desktop windows for movement
	EnumWindows((WNDENUMPROC)EnumWindowsFnCopyRect, (LPARAM) this);
}


// Window procedure for the Desktop window
LRESULT CALLBACK
DesktopWndProc(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	vncDesktop *_this = (vncDesktop*)GetWindowLong(hwnd, -21);// #define GWL_USERDATA        (-2

	switch (iMsg)
	{

		// GENERAL

	case WM_DISPLAYCHANGE:
		// The display resolution is changing

		// We must kick off any clients since their screen size will be wrong
		_this->m_displaychanged = TRUE;
		return 0;

	case WM_SYSCOLORCHANGE:
	case WM_PALETTECHANGED:
		// The palette colours have changed, so tell the server

		// Get the system palette
		if (!_this->SetPalette())
			PostQuitMessage(0);
		// Update any palette-based clients, too
		_this->m_server->UpdatePalette();
		return 0;

	case WM_TIMER:
		switch (wParam) {
		case vncDesktop::TIMER_POLL:
			_this->SetPollingFlag(true);
			break;
		case vncDesktop::TIMER_BLANK_SCREEN:
			if (_this->m_server->GetBlankScreen())
				_this->BlankScreen(TRUE);
			break;
		case vncDesktop::TIMER_RESTORE_SCREEN:
			_this->BlankScreen(FALSE);
			break;
		}
		return 0;

		// CLIPBOARD MESSAGES

	case WM_CHANGECBCHAIN:
		// The clipboard chain has changed - check our nextviewer handle
		if ((HWND)wParam == _this->m_hnextviewer)
			_this->m_hnextviewer = (HWND)lParam;
		else
			if (_this->m_hnextviewer != NULL)
				SendMessage(_this->m_hnextviewer,
							WM_CHANGECBCHAIN,
							wParam, lParam);

		return 0;

	case WM_DRAWCLIPBOARD:
		// The clipboard contents have changed
		if((GetClipboardOwner() != _this->Window()) &&
		    _this->m_initialClipBoardSeen &&
			_this->m_clipboard_active)
		{
			LPSTR cliptext = NULL;

			// Open the clipboard
			if (OpenClipboard(_this->Window()))
			{
				// Get the clipboard data
				HGLOBAL cliphandle = GetClipboardData(CF_TEXT);
				if (cliphandle != NULL)
				{
					LPSTR clipdata = (LPSTR) GlobalLock(cliphandle);

					// Copy it into a new buffer
					if (clipdata == NULL)
						cliptext = NULL;
					else
						cliptext = strdup(clipdata);

					// Release the buffer and close the clipboard
					GlobalUnlock(cliphandle);
				}

				CloseClipboard();
			}

			if (cliptext != NULL)
			{
				size_t cliplen = strlen(cliptext);
				LPSTR unixtext = (char *)malloc(cliplen+1);

				// Replace CR-LF with LF - never send CR-LF on the wire,
				// since Unix won't like it
				int unixpos=0;
				for (size_t x=0; x<cliplen; x++)
				{
					if (cliptext[x] != '\x0d')
					{
						unixtext[unixpos] = cliptext[x];
						unixpos++;
					}
				}
				unixtext[unixpos] = 0;

				// Free the clip text
				free(cliptext);
				cliptext = NULL;

				// Now send the unix text to the server
				_this->m_server->UpdateClipText(unixtext);

				free(unixtext);
			}
		}

		_this->m_initialClipBoardSeen = TRUE;

		if (_this->m_hnextviewer != NULL)
		{
			// Pass the message to the next window in clipboard viewer chain.  
			return SendMessage(_this->m_hnextviewer, WM_DRAWCLIPBOARD, 0,0); 
		}

		return 0;

	default:
		return DefWindowProc(hwnd, iMsg, wParam, lParam);
	}
}

BOOL vncDesktop::CheckUpdates()
{
#ifndef _DEBUG
	try
	{
#endif
		// Re-install polling timer if necessary
		if (m_server->PollingCycleChanged())
		{
			SetPollingTimer();
			m_server->PollingCycleChanged(false);
		}

		// Update the state of blank screen timer
		UpdateBlankScreenTimer();

		// Has the display resolution or desktop changed?
		if (m_displaychanged || !vncService::InputDesktopSelected() || !inConsoleSession())
		{

			rfbServerInitMsg oldscrinfo = m_scrinfo;
			m_displaychanged = FALSE;

			// Attempt to close the old hooks
			if (!Shutdown())
			{

				m_server->KillAuthClients();
				return FALSE;
			}

			// Now attempt to re-install them!
			ChangeResNow();

			if (!Startup())
			{

				m_server->KillAuthClients();
				return FALSE;
			}

			// Check if the screen info has changed

			// Call this regardless of screen format change
			m_server->UpdateLocalFormat();

			// Add a full screen update to all the clients
			m_changed_rgn.AddRect(m_bmrect);
			m_server->UpdatePalette();
		}

		// TRIGGER THE UPDATE

		RECT rect = m_server->GetSharedRect();
		RECT new_rect = GetSourceRect();
		IntersectRect(&new_rect, &new_rect, &m_bmrect);

		// Update screen size if required
		if (!EqualRect(&new_rect, &rect))
		{
			m_server->SetSharedRect(new_rect);
			bool sendnewfb = false;

			if (rect.right - rect.left != new_rect.right - new_rect.left ||
				rect.bottom - rect.top != new_rect.bottom - new_rect.top)
				sendnewfb = true;

			// FIXME: We should not send NewFBSize if a client
			//        did not send framebuffer update request.
			m_server->SetNewFBSize(sendnewfb);

			m_changed_rgn.Clear();

			if (sendnewfb && m_server->WindowShared())
			{
				if (new_rect.right - new_rect.left == 0 &&
					new_rect.bottom - new_rect.top == 0)
				{
// window is minimized
					return TRUE;
				}
				else
				{
// window is restored
// window is resized
					m_changed_rgn.AddRect(new_rect);
				}
			}
			else
			{
				return TRUE;
			}
		}

		// If we have clients full region requests
		if (m_server->FullRgnRequested())
		{
			// Capture screen to main buffer
			CaptureScreen(rect, m_mainbuff);
			// If we have a video driver - reset counter
			if ( m_videodriver != NULL && m_videodriver->IsActive())
			{
				m_videodriver->ResetCounter();
			}
		}

		// If we have incremental update requests
		if (m_server->IncrRgnRequested())
		{
			vncRegion rgn;

			// Use either a mirror video driver, or perform polling
			if (m_videodriver != NULL && m_videodriver->IsActive())
			{
				// FIXME: If there were no incremental update requests
				//        for some time, we will loose updates.
// IMPORTANT: Mirage outputs the regions re (0, 0)
// so we have to offset them re virtual display

// TODOTODO
					BOOL bCursorShape = FALSE;

					m_videodriver->HandleDriverChanges(
						this,
						m_changed_rgn,
						m_bmrect.left,
						m_bmrect.top,
						bCursorShape);
			}
			else
			{
				if (GetPollingFlag())
				{
					SetPollingFlag(false);
					PerformPolling();
				}
			}

			// Check for moved windows
// PrimaryDisplayOnlyShared: check if any problems when
// dragging from another display
			if ((m_server->FullScreen() || m_server->PrimaryDisplayOnlyShared()) &&
				!(m_videodriver && m_videodriver->IsHandlingScreen2ScreenBlt()))
			{
				CalcCopyRects();
			}

			if (m_copyrect_set)
			{
				// Send copyrect to all clients
				m_server->CopyRect(m_copyrect_rect, m_copyrect_src);
				m_copyrect_set = false;

// DEBUG: Continue auditing the code from this point.

// IMPORTANT: this order: CopyRectToBuffer, CaptureScreen, GetChangedRegion
				// Copy old window rect to back buffer
				CopyRectToBuffer(m_copyrect_rect, m_copyrect_src);

				// Copy new window rect to main buffer
				CaptureScreen(m_copyrect_rect, m_mainbuff);

				// Get changed pixels to rgn
				GetChangedRegion(rgn, m_copyrect_rect);

				RECT rect;
				rect.left= m_copyrect_src.x;
				rect.top = m_copyrect_src.y;
				rect.right = rect.left + (m_copyrect_rect.right - m_copyrect_rect.left);
				rect.bottom = rect.top + (m_copyrect_rect.bottom - m_copyrect_rect.top);
				// Refresh old window rect
				m_changed_rgn.AddRect(rect);
				// Don't refresh new window rect
				m_changed_rgn.SubtractRect(m_copyrect_rect);
			} 

			// Get only desktop area
			vncRegion temprgn;
			temprgn.Clear();
			temprgn.AddRect(rect);
			m_changed_rgn.Intersect(temprgn);

			// Get list of rectangles for checking
			rectlist rectsToScan;
			m_changed_rgn.Rectangles(rectsToScan);

			// Capture and check them
			CheckRects(rgn, rectsToScan);

			// Update the mouse
			m_server->UpdateMouse();

			// Send changed region data to all clients
			m_server->UpdateRegion(rgn);

			// Clear changed region
			m_changed_rgn.Clear();
		}

		// Trigger an update to be sent
		if (m_server->FullRgnRequested() || m_server->IncrRgnRequested())
		{
			m_server->TriggerUpdate();
		}

#ifndef _DEBUG
	}
	catch (...)
	{
		m_server->KillAuthClients();
		return FALSE;
	}
#endif

	return TRUE;
}

void
vncDesktop::SetPollingTimer()
{
	const UINT driverCycle = 30;
	const UINT minPollingCycle = 5;

	UINT msec;
	if (m_videodriver != NULL) {
		msec = driverCycle;
	} else {
		msec = m_server->GetPollingCycle() / 16;
		if (msec < minPollingCycle) {
			msec = minPollingCycle;
		}
	}
	m_timer_polling = (UINT)SetTimer(Window(), TIMER_POLL, msec, NULL);
}

inline void vncDesktop::CheckRects(vncRegion &rgn, rectlist &rects)
{
#ifndef _DEBUG
	try
	{
#endif
		rectlist::iterator i;

		for (i = rects.begin(); i != rects.end(); i++)
		{
			// Copy data to the main buffer
			// FIXME: Maybe call CaptureScreen() just once?
			//        Check what would be more efficient.
			CaptureScreen(*i, m_mainbuff);

// Check for changes in the rectangle
			GetChangedRegion(rgn, *i);
		}
#ifndef _DEBUG
	}
	catch (...)
	{
		throw;
	}
#endif
}

// This notably improves performance when using Visual C++ 6.0 compiler
#pragma function(memcpy, memcmp)

static const int BLOCK_SIZE = 32;

/*
// A dummy version of GetChangedRegion() created for troubleshoot purposes
// when GetChangedRegion() et al are suspected for bugs/need changes.
// The code below is as simple and clear as possible.
void vncDesktop::GetChangedRegion(vncRegion &rgn, const RECT &rect)
{
	rgn.AddRect(rect);

	// Copy the changes to the back buffer
	const int c2rect_re_vd_top = rect.top - m_bmrect.top;
	const int c3rect_re_vd_left = rect.left - m_bmrect.left;
	_ASSERTE(c2rect_re_vd_top >= 0);
	_ASSERTE(c3rect_re_vd_left >= 0);

	const UINT bytesPerPixel = m_scrinfo.format.bitsPerPixel / 8;
	const int offset = c2rect_re_vd_top * m_bytesPerRow + c3rect_re_vd_left * bytesPerPixel;

	unsigned char *o_ptr = m_backbuff + offset;
	unsigned char *n_ptr = m_mainbuff + offset;
	const int bytes_in_row = (rect.right - rect.left) * bytesPerPixel;
	for (int y = rect.top; y < rect.bottom; y++)
	{
		memcpy(o_ptr, n_ptr, bytes_in_row);
		n_ptr += m_bytesPerRow;
		o_ptr += m_bytesPerRow;
	}
}
*/

/*
// DEBUG: Another dumb and slow version of GetChangedRegion().
void vncDesktop::GetChangedRegion(vncRegion &rgn, const RECT &rect)
{
	RECT newRect;


	// Copy the changes to the back buffer
	const int top = rect.top - m_bmrect.top;
	const int left = rect.left - m_bmrect.left;
	_ASSERTE(top >= 0);
	_ASSERTE(left >= 0);

	const UINT bytesPerPixel = m_scrinfo.format.bitsPerPixel / 8;
	const int offset = top * m_bytesPerRow + left * bytesPerPixel;

	unsigned char *o_ptr = m_backbuff + offset;
	unsigned char *n_ptr = m_mainbuff + offset;
	const int bytes_in_row = (rect.right - rect.left) * bytesPerPixel;
	for (int y = rect.top; y < rect.bottom; y++) {
		int x0 = rect.left;
		while (x0 < rect.right) {
			unsigned char *pNew = m_mainbuff + y * m_bytesPerRow + x0 * bytesPerPixel;
			unsigned char *pOld = m_backbuff + y * m_bytesPerRow + x0 * bytesPerPixel;
			if (memcmp(pOld, pNew, bytesPerPixel) != 0) {
				break;	// x0 points to the first difference at the left
			}
			x0++;
		}
		SetRect(&newRect, x0, y, rect.right, y + 1);
		if (newRect.right - newRect.left > 0 && newRect.bottom - newRect.top > 0) {
			rgn.AddRect(newRect);
		}

		memcpy(o_ptr, n_ptr, bytes_in_row);
		n_ptr += m_bytesPerRow;
		o_ptr += m_bytesPerRow;
	}
}
*/

void vncDesktop::GetChangedRegion(vncRegion &rgn, const RECT &rect)
{
	const UINT bytesPerPixel = m_scrinfo.format.bitsPerPixel / 8;
	const int bytes_per_scanline = (rect.right - rect.left) * bytesPerPixel;

	const int crect_re_vd_left = rect.left - m_bmrect.left;
	const int crect_re_vd_top = rect.top - m_bmrect.top;
	_ASSERTE(crect_re_vd_left >= 0);
	_ASSERTE(crect_re_vd_top >= 0);

	const int offset = crect_re_vd_top * m_bytesPerRow + crect_re_vd_left * bytesPerPixel;
	unsigned char *o_ptr = m_backbuff + offset;
	unsigned char *n_ptr = m_mainbuff + offset;

	RECT new_rect = rect;

	// Fast processing for small rectangles
	if (rect.right - rect.left <= BLOCK_SIZE &&
		rect.bottom - rect.top <= BLOCK_SIZE)
	{
		for (int y = rect.top; y < rect.bottom; y++)
		{
			if (memcmp(o_ptr, n_ptr, bytes_per_scanline) != 0)
			{
				new_rect.top = y;
				UpdateChangedSubRect(rgn, new_rect);
				break;
			}
			o_ptr += m_bytesPerRow;
			n_ptr += m_bytesPerRow;
		}
		return;
	}

// Process bigger rectangles
	BOOL bTop4Move = TRUE;
	for (int y = rect.top; y < rect.bottom; y++)
	{
		if (memcmp(o_ptr, n_ptr, bytes_per_scanline) != 0)
		{
			if (bTop4Move)
			{
				new_rect.top = y;
				bTop4Move = FALSE;
			}
			// Skip a number of lines after a non-matched one
			int n = BLOCK_SIZE / 2 - 1;
			y += n;
			o_ptr += n * m_bytesPerRow;
			n_ptr += n * m_bytesPerRow;
		}
		else
		{
			if (!bTop4Move)
			{
				new_rect.bottom = y;
				UpdateChangedRect(rgn, new_rect);
				bTop4Move = TRUE;
			}
		}
		o_ptr += m_bytesPerRow;
		n_ptr += m_bytesPerRow;
	}
	if (!bTop4Move)
	{
		new_rect.bottom = rect.bottom;
		UpdateChangedRect(rgn, new_rect);
	}
}

void vncDesktop::UpdateChangedRect(vncRegion &rgn, const RECT &rect)
{
	// Pass small rectangles directly to UpdateChangedSubRect
	if (rect.right - rect.left <= BLOCK_SIZE &&
		rect.bottom - rect.top <= BLOCK_SIZE)
	{
		UpdateChangedSubRect(rgn, rect);
		return;
	}

	const UINT bytesPerPixel = m_scrinfo.format.bitsPerPixel / 8;

	RECT new_rect;
	int x, y, ay;

	const int crect_re_vd_left = rect.left - m_bmrect.left;
	const int crect_re_vd_top = rect.top - m_bmrect.top;
	_ASSERTE(crect_re_vd_left >= 0);
	_ASSERTE(crect_re_vd_top >= 0);

	// Scan down the rectangle
	const int offset = crect_re_vd_top * m_bytesPerRow + crect_re_vd_left * bytesPerPixel;
	unsigned char *o_topleft_ptr = m_backbuff + offset;
	unsigned char *n_topleft_ptr = m_mainbuff + offset;

	for (y = rect.top; y < rect.bottom; y += BLOCK_SIZE)
	{
		// Work out way down the bitmap
		unsigned char *o_row_ptr = o_topleft_ptr;
		unsigned char *n_row_ptr = n_topleft_ptr;

		const int blockbottom = Min(y + BLOCK_SIZE, rect.bottom);
		new_rect.bottom = blockbottom;

		BOOL bLeft4Move = TRUE;

		for (x = rect.left; x < rect.right; x += BLOCK_SIZE)
		{
			// Work our way across the row
			unsigned char *n_block_ptr = n_row_ptr;
			unsigned char *o_block_ptr = o_row_ptr;

			const UINT blockright = Min(x + BLOCK_SIZE, rect.right);
			const UINT bytesPerBlockRow = (blockright-x) * bytesPerPixel;

			// Scan this block
			for (ay = y; ay < blockbottom; ay++)
			{
				if (memcmp(n_block_ptr, o_block_ptr, bytesPerBlockRow) != 0)
					break;
				n_block_ptr += m_bytesPerRow;
				o_block_ptr += m_bytesPerRow;
			}
			if (ay < blockbottom)
			{
				// There were changes, so this block will need to be updated
				if (bLeft4Move)
				{
					new_rect.left = x;
					bLeft4Move = FALSE;
					new_rect.top = ay;
				}
				else if (ay < new_rect.top)
				{
					new_rect.top = ay;
				}
			}
			else
			{
				// No changes in this block, process previous changed blocks if any
				if (!bLeft4Move)
				{
					new_rect.right = x;
					UpdateChangedSubRect(rgn, new_rect);
					bLeft4Move = TRUE;
				}
			}

			o_row_ptr += bytesPerBlockRow;
			n_row_ptr += bytesPerBlockRow;
		}

		if (!bLeft4Move)
		{
			new_rect.right = rect.right;
			UpdateChangedSubRect(rgn, new_rect);
		}

		o_topleft_ptr += m_bytesPerRow * BLOCK_SIZE;
		n_topleft_ptr += m_bytesPerRow * BLOCK_SIZE;
	}
}

void vncDesktop::UpdateChangedSubRect(vncRegion &rgn, const RECT &rect)
{
	const UINT bytesPerPixel = m_scrinfo.format.bitsPerPixel / 8;
	int bytes_in_row = (rect.right - rect.left) * bytesPerPixel;
	int y, i;

	const int crect_re_vd_left = rect.left - m_bmrect.left;
	const int crect_re_vd_bottom = rect.bottom - m_bmrect.top;
	_ASSERTE(crect_re_vd_left >= 0);
	_ASSERTE(crect_re_vd_bottom >= 0);

	// Exclude unchanged scan lines at the bottom
	int offset = (crect_re_vd_bottom - 1) * m_bytesPerRow + crect_re_vd_left * bytesPerPixel;
	unsigned char *o_ptr = m_backbuff + offset;
	unsigned char *n_ptr = m_mainbuff + offset;
	RECT final_rect = rect;
	final_rect.bottom = rect.top + 1;
	for (y = rect.bottom - 1; y > rect.top; y--)
	{
		if (memcmp(o_ptr, n_ptr, bytes_in_row) != 0)
		{
			final_rect.bottom = y + 1;
			break;
		}
		n_ptr -= m_bytesPerRow;
		o_ptr -= m_bytesPerRow;
	}

	// Exclude unchanged pixels at left and right sides
	const int c2rect_re_vd_left = final_rect.left - m_bmrect.left;
	const int c2rect_re_vd_top = final_rect.top - m_bmrect.top;
	_ASSERTE(c2rect_re_vd_left >= 0);
	_ASSERTE(c2rect_re_vd_top >= 0);

	offset = c2rect_re_vd_top * m_bytesPerRow + c2rect_re_vd_left * bytesPerPixel;
	o_ptr = m_backbuff + offset;
	n_ptr = m_mainbuff + offset;
	int left_delta = bytes_in_row - 1;
	int right_delta = 0;
	for (y = final_rect.top; y < final_rect.bottom; y++)
	{
		for (i = 0; i < bytes_in_row - 1; i++)
		{
			if (n_ptr[i] != o_ptr[i])
			{
				if (i < left_delta)
					left_delta = i;
				break;
			}
		}
		for (i = bytes_in_row - 1; i > 0; i--)
		{
			if (n_ptr[i] != o_ptr[i])
			{
				if (i > right_delta)
					right_delta = i;
				break;
			}
		}
		n_ptr += m_bytesPerRow;
		o_ptr += m_bytesPerRow;
	}
	final_rect.right = final_rect.left + right_delta / bytesPerPixel + 1;
	final_rect.left += left_delta / bytesPerPixel;

	// Update the rectangle
	rgn.AddRect(final_rect);

	// Copy the changes to the back buffer
	const int c3rect_re_vd_left = final_rect.left - m_bmrect.left;
	_ASSERTE(c3rect_re_vd_left >= 0);

	offset = c2rect_re_vd_top * m_bytesPerRow + c3rect_re_vd_left * bytesPerPixel;

	o_ptr = m_backbuff + offset;
	n_ptr = m_mainbuff + offset;
	bytes_in_row = (final_rect.right - final_rect.left) * bytesPerPixel;
	for (y = final_rect.top; y < final_rect.bottom; y++)
	{
		memcpy(o_ptr, n_ptr, bytes_in_row);
		n_ptr += m_bytesPerRow;
		o_ptr += m_bytesPerRow;
	}
}


void vncDesktop::PerformPolling()
{
	if (m_server->PollFullScreen())
	{
		// Poll full screen
		RECT full_rect = m_server->GetSharedRect();
		PollArea(full_rect);
	}
	else
	{
		// Poll a window
		if (m_server->PollForeground())
		{
			// Get the window rectangle for the currently selected window
			HWND hwnd = GetForegroundWindow();
			if (hwnd != NULL)
				PollWindow(hwnd);
		}
		if (m_server->PollUnderCursor())
		{
			// Find the mouse position
			POINT mousepos;
			if (GetCursorPos(&mousepos))
			{
				// Find the window under the mouse
				HWND hwnd = WindowFromPoint(mousepos);
				if (hwnd != NULL)
					PollWindow(hwnd);
			}
		}
	}
}

void
vncDesktop::PollWindow(HWND hwnd)
{
	// Are we set to low-load polling?
	if (m_server->PollOnEventOnly())
	{
		// Yes, so only poll if the remote user has done something
		if (!m_server->RemoteEventReceived()) {
			return;
		}
	}

	// Does the client want us to poll only console windows?
	if (m_server->PollConsoleOnly())
	{
		char classname[20];

		// Yes, so check that this is a console window...
		if (GetClassName(hwnd, classname, sizeof(classname))) {
			if ((strcmp(classname, "tty") != 0) &&
				(strcmp(classname, "ConsoleWindowClass") != 0)) {
				return;
			}
		}
	}

	RECT full_rect = m_server->GetSharedRect();
	RECT rect;

	// Get the rectangle
	if (GetWindowRect(hwnd, &rect)) {
		if (IntersectRect(&rect, &rect, &full_rect)) {
			PollArea(rect);
		}
	}
}

//
// Implementation of the polling algorithm.
//

void vncDesktop::PollArea(const RECT &rect)
{
	const int scanLine = m_pollingOrder[m_pollingStep++ % 32];
	const UINT bytesPerPixel = m_scrinfo.format.bitsPerPixel / 8;

	// Align 32x32 tiles to the left top corner of the shared area
	const RECT shared = m_server->GetSharedRect();
	const int leftAligned = ((rect.left - shared.left) & 0xFFFFFFE0) + shared.left;
	const int topAligned = ((rect.top - shared.top) & 0xFFFFFFE0) + shared.top;

	RECT rowRect = rect;	// we'll need left and right borders

	for (int y = topAligned; y < rect.bottom; y += 32)
	{
		const int tile_h = min(rect.bottom - y, 32);
// TODO: refactor it
		int sl = scanLine;
// window captions suffer an arbitrary scanline...
		if (y == topAligned)
			sl = 31;
		sl = min(sl, tile_h-1);
		const int scan_y = y + sl;

		_ASSERTE(scan_y >= rect.top);
		_ASSERTE(scan_y < rect.bottom);

		rowRect.top = scan_y;
		rowRect.bottom = scan_y + 1;
		CaptureScreen(rowRect, m_mainbuff);
		const int offset = (scan_y-m_bmrect.top) * m_bytesPerRow + (leftAligned-m_bmrect.left) * bytesPerPixel;
		const unsigned char *o_ptr = m_backbuff + offset;
		const unsigned char *n_ptr = m_mainbuff + offset;
		for (int x = leftAligned; x < rect.right; x += 32)
		{
			const int tile_w = min(rect.right - x, 32);
			const int nBytes = tile_w * bytesPerPixel;
			if (memcmp(o_ptr, n_ptr, nBytes) != 0)
			{
				RECT tileRect;
				tileRect.left = x;
				tileRect.top = y;
				tileRect.right = x + tile_w;
				tileRect.bottom = y + tile_h;
				m_changed_rgn.AddRect(tileRect);
			}
			o_ptr += nBytes;
			n_ptr += nBytes;
		}
	}
}

void vncDesktop::CopyRect(const RECT &rcDest, const POINT &ptSrc)
{
	const int offset_x = rcDest.left - ptSrc.x;
	const int offset_y = rcDest.top - ptSrc.y;

	// Clip the destination to the screen
	RECT destrect;
	if (!IntersectRect(&destrect, &rcDest, &m_server->GetSharedRect()))
		return;

	// NOTE: This is important. Each pixel in destrect is either salvaged
	//       by copyrect or became dirty.
	m_changed_rgn.AddRect(destrect);

	// Work out the source rectangle
	RECT srcrect;
	srcrect.left = destrect.left - offset_x;
	srcrect.top = destrect.top - offset_y;
	srcrect.right = srcrect.left + destrect.right - destrect.left;
	srcrect.bottom = srcrect.top + destrect.bottom - destrect.top;

	// Clip the source to the screen
	RECT srcrect2;
	if (!IntersectRect(&srcrect2, &srcrect, &m_server->GetSharedRect()))
		return;

	destrect.left += (srcrect2.left - srcrect.left);
	destrect.top += (srcrect2.top - srcrect.top);
	destrect.right = srcrect2.right - srcrect2.left + destrect.left;
	destrect.bottom = srcrect2.bottom - srcrect2.top + destrect.top;

	if ( destrect.right - destrect.left >= 16 &&
		 destrect.bottom - destrect.top >= 16 ) {
		m_changed_rgn.SubtractRect(destrect);

		m_copyrect_rect = destrect;
		m_copyrect_src.x = srcrect2.left;
		m_copyrect_src.y = srcrect2.top;
		m_copyrect_set = TRUE;

		//DPF(("CopyRect: (%d, %d) (%d, %d, %d, %d)\n",
		//	m_copyrect_src.x,
		//	m_copyrect_src.y,
		//	m_copyrect_rect.left,
		//	m_copyrect_rect.top,
		//	m_copyrect_rect.right,
		//	m_copyrect_rect.bottom));
	}
}

//
// Copy the data from one rectangle of the back buffer to another.
//

void vncDesktop::CopyRectToBuffer(const RECT &dest, const POINT &source)
{
	const int src_x = source.x - m_bmrect.left;
	const int src_y = source.y - m_bmrect.top;
	_ASSERTE(src_x >= 0);
	_ASSERTE(src_y >= 0);

	const int dst_x = dest.left - m_bmrect.left;
	const int dst_y = dest.top - m_bmrect.top;
	_ASSERTE(dst_x >= 0);
	_ASSERTE(dst_y >= 0);

	const unsigned int bytesPerPixel = m_scrinfo.format.bitsPerPixel / 8;
	const unsigned int bytesPerLine = (dest.right - dest.left) * bytesPerPixel;

	BYTE *srcptr = m_backbuff + src_y * m_bytesPerRow + src_x * bytesPerPixel;
	BYTE *destptr = m_backbuff + dst_y * m_bytesPerRow + dst_x * bytesPerPixel;

	if (dst_y < src_y) {
		for (int y = dest.top; y < dest.bottom; y++) {
			memmove(destptr, srcptr, bytesPerLine);
			srcptr += m_bytesPerRow;
			destptr += m_bytesPerRow;
		}
	} else {
		srcptr += m_bytesPerRow * (dest.bottom - dest.top - 1);
		destptr += m_bytesPerRow * (dest.bottom - dest.top - 1);
		for (int y = dest.bottom; y > dest.top; y--) {
			memmove(destptr, srcptr, bytesPerLine);
			srcptr -= m_bytesPerRow;
			destptr -= m_bytesPerRow;
		}
	}
}

BOOL	IsBadDirectAccessConfig()
{
	if (IsWinVerOrHigher(5, 1))
	{
		if (GetSystemMetrics(SM_XVIRTUALSCREEN) < 0)
			return TRUE;
		if (GetSystemMetrics(SM_YVIRTUALSCREEN) < 0)
			return TRUE;
	}
	return FALSE;
}

BOOL vncDesktop::InitVideoDriver()
{
	// Mirror video drivers supported under Win2K, WinXP, WinVista
	// and Windows NT 4.0 SP3 (we assume SP6).
	if (!vncService::IsWinNT())
		return FALSE;

	// FIXME: Windows NT 4.0 support is broken and thus we disable it here.
	if (!IsWinVerOrHigher(5, 0))
		return FALSE;

	if (m_server->DontUseDriver())
	{
		return FALSE;
	}

	BOOL	bIsBadDASDConfig = IsBadDirectAccessConfig();


	BOOL	bSolicitDASD = m_server->DriverDirectAccess() & !bIsBadDASDConfig;

	_ASSERTE(!m_videodriver);
	m_videodriver = new vncVideoDriver;
	if (!m_videodriver)
	{
		return FALSE;
	}

	if (IsWinVerOrHigher(5, 0))
	{
// restart the driver if left running.
// NOTE that on NT4 it must be running beforehand
		if (m_videodriver->TestMapped())
		{
			m_videodriver->Deactivate();
		}
		_ASSERTE(!m_videodriver->TestMapped());
	}

	{
		RECT	vdesk_rect;
		GetSourceDisplayRect(vdesk_rect);
		BOOL b = m_videodriver->Activate(bSolicitDASD, &vdesk_rect);
	}

	if (!m_videodriver->CheckVersion())
	{

// IMPORTANT: fail on NT46
		if (IsNtVer(4, 0))
			return FALSE;
	}

	if (m_videodriver->MapSharedbuffers(bSolicitDASD))
	{

	}
	else
	{
		delete m_videodriver;
		m_videodriver = NULL;

		return FALSE;
	}
	_ASSERTE(bSolicitDASD == m_videodriver->IsDirectAccessInEffect());
	return TRUE;
}

void vncDesktop::ShutdownVideoDriver()
{
	if (m_videodriver == NULL)
		return;
	delete m_videodriver;
	m_videodriver = NULL;

}

void
vncDesktop::UpdateBlankScreenTimer()
{
	BOOL active = m_server->GetBlankScreen();
	if (active && !m_timer_blank_screen) {
		m_timer_blank_screen = (UINT)SetTimer(Window(), TIMER_BLANK_SCREEN, 50, NULL);
	} else if (!active && m_timer_blank_screen) {
		KillTimer(Window(), TIMER_BLANK_SCREEN);
		m_timer_blank_screen = 0;
		PostMessage(m_hwnd, WM_TIMER, TIMER_RESTORE_SCREEN, 0);
	}
}

void
vncDesktop::BlankScreen(BOOL set)
{
	if (set) {
		SystemParametersInfo(SPI_SETPOWEROFFACTIVE, 1, NULL, 0);
		SendMessage(GetDesktopWindow(), WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)2);
	} else {
		SystemParametersInfo(SPI_SETPOWEROFFACTIVE, 0, NULL, 0);
		SendMessage(GetDesktopWindow(), WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)-1);
	}
}

// created for debug purposes
bool	SaveBitmapToBMPFile(
			HANDLE hFile,
			void *ptrBm,
			void *ptrPal,
			int bmwidth,
			int bmheight,
			int bmstride,
			int bmclrdepth)
{
	BITMAPINFOHEADER bih = {0};
	bih.biSize			= sizeof(bih);
	bih.biWidth			= bmwidth;
	bih.biHeight		= bmheight;
	bih.biPlanes		= 1;
	bih.biCompression	= BI_RGB;

	DWORD bitFields[3] = {0, 0, 0};

	if (bmclrdepth == 1)
	{
		bih.biBitCount = 1;
		bih.biClrUsed = 2;
	}
	else if (bmclrdepth == 2)
	{
		bih.biBitCount = 2;
		bih.biClrUsed = 4;
	}
	else if (bmclrdepth == 4)
	{
		bih.biBitCount = 4;
		bih.biClrUsed = 0x10;
	}
	else if (bmclrdepth == 8)
	{
		bih.biBitCount = 8;
		bih.biClrUsed = 0x100;
	}
	else if (bmclrdepth == 16)
	{
		bih.biBitCount = 16;
		bih.biCompression = BI_BITFIELDS;
// TODO: use actual masks
		bitFields[0] = 0xF800;
		bitFields[1] = 0x07E0;
		bitFields[2] = 0x001F;
	}
	else if (bmclrdepth == 24)
	{
		bih.biBitCount = 24;
	}
	else if (bmclrdepth == 32)
	{
		bih.biBitCount = 32;
	}
	else
		_ASSERTE(false);

	BITMAPFILEHEADER bfh = {0};
	bfh.bfType			= 0x4d42;	// 0x42 = "B" 0x4d = "M" 
	bfh.bfOffBits		= sizeof(BITMAPFILEHEADER) + bih.biSize;

	if (bih.biClrUsed)
	{
		bfh.bfOffBits += bih.biClrUsed * sizeof(RGBQUAD);
	}
	else if (bitFields[0] || bitFields[1] || bitFields[2])
	{
		bfh.bfOffBits += sizeof(bitFields);
	}

	unsigned lineSize = (((bih.biWidth * bih.biBitCount) + 15) / 8) & ~1;
	bfh.bfSize = bfh.bfOffBits + lineSize * bih.biHeight; 

	ULONG ulnWr = 0;
	if (!WriteFile(hFile, &bfh, sizeof(bfh), &ulnWr, NULL) || ulnWr!=sizeof(bfh))
		return false;
	if (!WriteFile(hFile, &bih, sizeof(bih), &ulnWr, NULL) || ulnWr!=sizeof(bih))
		return false;

	if (ptrPal)
	{
		if (!WriteFile(hFile, ptrPal, bih.biClrUsed * sizeof(RGBQUAD), &ulnWr, NULL) || ulnWr!=bih.biClrUsed * sizeof(RGBQUAD))
			return false;
	}
	else if (bih.biCompression == BI_BITFIELDS)
	{
		if (!WriteFile(hFile, bitFields, sizeof(bitFields), &ulnWr, NULL) || ulnWr!=sizeof(bitFields))
			return false;
	}

	for (int i = 0; i < bih.biHeight; i++)
	{
		char *pDWr = (char*)ptrBm + (bih.biHeight - i - 1) * bmstride;
		if (!WriteFile(hFile, pDWr, lineSize, &ulnWr, NULL) || ulnWr!=lineSize)
			return false;
	}

	return true;
}

// created for debug purposes
bool	bDbgBmDump(
			void *ptr,
			int bmwidth,
			int bmheight,
			int bmstride,
			int bmclrdepth)
{
	if (bmclrdepth!=16 && bmclrdepth!=32)
	{
		// TODO: add 8 bpp
		return false;
	}

	SYSTEMTIME stm;
	GetSystemTime(&stm);
	TCHAR szFileName[MAX_PATH];
	sprintf(
		szFileName,
		"%04u.%02u.%02u-%02u-%02u-%02u-0x%08p.bmp",
		stm.wYear, stm.wMonth, stm.wDay,
		stm.wHour, stm.wMinute, stm.wSecond,
		ptr);

	HANDLE hFile = CreateFile(
		szFileName,
		FILE_WRITE_DATA,
		0,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile==INVALID_HANDLE_VALUE)
	{
		return false;
	}

	bool b= SaveBitmapToBMPFile(
		hFile,
		ptr,
		NULL,
		bmwidth,
		bmheight,
		bmstride,
		bmclrdepth);

	CloseHandle(hFile);
	return b;
}

// created for debug purposes
bool	vncDesktop::bDbgDumpSurfBuffers(const RECT &rcl)
{
	const int c2rect_re_vd_top = rcl.top - m_bmrect.top;
	const int c3rect_re_vd_left = rcl.left - m_bmrect.left;
	_ASSERTE(c2rect_re_vd_top >= 0);
	_ASSERTE(c3rect_re_vd_left >= 0);
	const UINT bytesPerPixel = m_scrinfo.format.bitsPerPixel / 8;
	const int offset = c2rect_re_vd_top * m_bytesPerRow + c3rect_re_vd_left * bytesPerPixel;

	bool b1 = bDbgBmDump(
		m_mainbuff+offset,
		rcl.right - rcl.left,
		rcl.bottom - rcl.top,
		m_bytesPerRow,
		m_scrinfo.format.bitsPerPixel);

	bool b2 = bDbgBmDump(
		m_backbuff+offset,
		rcl.right - rcl.left,
		rcl.bottom - rcl.top,
		m_bytesPerRow,
		m_scrinfo.format.bitsPerPixel);
	return b1 && b2;
}
