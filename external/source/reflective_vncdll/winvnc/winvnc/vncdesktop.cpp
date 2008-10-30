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

// vncDesktop implementation

// System headers
#include <assert.h>
#include "stdhdrs.h"

// Custom headers
#include <omnithread.h>
#include "WinVNC.h"
#include "VNCHooks\VNCHooks.h"
#include "vncServer.h"
#include "vncKeymap.h"
#include "rfbRegion.h"
#include "rfbRect.h"
#include "vncDesktop.h"
#include "vncService.h"

// Constants
const UINT RFB_SCREEN_UPDATE = RegisterWindowMessage("WinVNC.Update.DrawRect");
const UINT RFB_COPYRECT_UPDATE = RegisterWindowMessage("WinVNC.Update.CopyRect");
const UINT RFB_MOUSE_UPDATE = RegisterWindowMessage("WinVNC.Update.Mouse");
const char szDesktopSink[] = "WinVNC desktop sink";

// The desktop handler thread
// This handles the messages posted by RFBLib to the vncDesktop window

class vncDesktopThread : public omni_thread
{
public:
	vncDesktopThread() {m_returnsig = NULL;};
protected:
	~vncDesktopThread() {if (m_returnsig != NULL) delete m_returnsig;};
public:
	virtual BOOL Init(vncDesktop *desktop, vncServer *server);
	virtual void *run_undetached(void *arg);
	virtual void ReturnVal(BOOL result);
	void PollWindow(rfb::Region2D &rgn, HWND hwnd);
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

void
vncDesktopThread::PollWindow(rfb::Region2D &rgn, HWND hwnd)
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
	if (m_desktop->m_server->PollConsoleOnly())
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

	RECT rect;

	// Get the rectangle
	if (GetWindowRect(hwnd, &rect)) {
		rfb::Rect wrect = rfb::Rect(rect).intersect(m_desktop->m_bmrect);
		if (!wrect.is_empty()) {
			rgn = rgn.union_(rfb::Region2D(wrect));
		}
	}
}

void *
vncDesktopThread::run_undetached(void *arg)
{
	// Save the thread's "home" desktop, under NT (no effect under 9x)
	HDESK home_desktop = GetThreadDesktop(GetCurrentThreadId());

	// Attempt to initialise and return success or failure
	if (!m_desktop->Startup())
	{
		vncService::SelectHDESK(home_desktop);
		ReturnVal(FALSE);
		return NULL;
	}

  // Grab the initial display contents
  // *** m_desktop->m_buffer.GrabRegion(m_desktop->m_bmrect);
  // *** m_desktop->m_buffer.Clear(m_desktop->m_bmrect);

	// Succeeded to initialise ok
	ReturnVal(TRUE);

	// START PROCESSING DESKTOP MESSAGES

	// We set a flag inside the desktop handler here, to indicate it's now safe
	// to handle clipboard messages
	m_desktop->SetClipboardActive(TRUE);

	// All changes in the state of the display are stored in a local
	// UpdateTracker object, and are flushed to the vncServer whenever
	// client updates are about to be triggered
	rfb::SimpleUpdateTracker clipped_updates;
	rfb::ClippedUpdateTracker updates(clipped_updates, m_desktop->m_bmrect);
	clipped_updates.enable_copyrect(true);

	// Incoming update messages are collated into a single region cache
	// The region cache areas are checked for changes before an update
	// is triggered, and the changed areas are passed to the UpdateTracker
	rfb::Region2D rgncache = m_desktop->m_bmrect;

	// The previous cursor position is stored, to allow us to erase the
	// old instance whenever it moves.
	rfb::Point oldcursorpos;

	// Set the hook thread to a high priority
	// *** set_priority(omni_thread::PRIORITY_HIGH);

	BOOL idle_skip = TRUE;
	ULONG idle_skip_count = 0;
	MSG msg;
	while (TRUE)
	{
		if (!PeekMessage(&msg, NULL, NULL, NULL, PM_REMOVE)) {
			//
			// - MESSAGE QUEUE EMPTY
			// Whenever the message queue becomes empty, we check to see whether
			// there are updates to be passed to clients.
			if (idle_skip) {
				idle_skip = FALSE;
				if (idle_skip_count++ < 4) {
					Sleep(5);
					continue;
				}
			}
			idle_skip_count = 0;

			// Clear the triggered flag
			m_desktop->m_update_triggered = FALSE;

			//
			// CHECK SCREEN FORMAT
			// First, we must check that the screen hasnt changed too much.
			if (m_desktop->m_displaychanged || !vncService::InputDesktopSelected())
			{
				rfbServerInitMsg oldscrinfo = m_desktop->m_scrinfo;
				m_desktop->m_displaychanged = FALSE;

				// Attempt to close the old hooks
				if (!m_desktop->Shutdown())
				{
					m_server->KillAuthClients();
					break;
				}

				// Now attempt to re-install them!
				if (!m_desktop->Startup())
				{
					m_server->KillAuthClients();
					break;
				}

				// Check that the screen info hasn't changed
				//vnclog.Print(LL_INTINFO, VNCLOG("SCR: old screen format %dx%dx%d\n"),
				//	oldscrinfo.framebufferWidth,
				//	oldscrinfo.framebufferHeight,
				//	oldscrinfo.format.bitsPerPixel);
				//vnclog.Print(LL_INTINFO, VNCLOG("SCR: new screen format %dx%dx%d\n"),
				//	m_desktop->m_scrinfo.framebufferWidth,
				//	m_desktop->m_scrinfo.framebufferHeight,
				//	m_desktop->m_scrinfo.format.bitsPerPixel);
				if ((m_desktop->m_scrinfo.framebufferWidth != oldscrinfo.framebufferWidth) ||
					(m_desktop->m_scrinfo.framebufferHeight != oldscrinfo.framebufferHeight))
				{
					m_server->KillAuthClients();
					break;
				} else if (memcmp(&m_desktop->m_scrinfo.format, &oldscrinfo.format, sizeof(rfbPixelFormat)) != 0)
				{
					m_server->UpdateLocalFormat();
				}

				// Adjust the UpdateTracker clip region
				updates.set_clip_region(m_desktop->m_bmrect);

				// Add a full screen update to all the clients
				rgncache = rgncache.union_(rfb::Region2D(m_desktop->m_bmrect));
				m_server->UpdatePalette();
			}
	
			//
			// CALCULATE CHANGES
			//

			if (m_desktop->m_server->UpdateWanted())
			{
				// POLL PROBLEM AREAS
				// We add specific areas of the screen to the region cache,
				// causing them to be fetched for processing.
				if (m_desktop->m_server->PollFullScreen())
				{
					rfb::Rect rect = m_desktop->m_qtrscreen;
					rect = rect.translate(rfb::Point(0, m_desktop->m_pollingcycle * m_desktop->m_qtrscreen.br.y));
					rgncache = rgncache.union_(rfb::Region2D(rect));
					m_desktop->m_pollingcycle = (m_desktop->m_pollingcycle + 1) % 4;
				}
				if (m_desktop->m_server->PollForeground())
				{
					// Get the window rectangle for the currently selected window
					HWND hwnd = GetForegroundWindow();
					if (hwnd != NULL)
						PollWindow(rgncache, hwnd);
				}
				if (m_desktop->m_server->PollUnderCursor())
				{
					// Find the mouse position
					POINT mousepos;
					if (GetCursorPos(&mousepos))
					{
						// Find the window under the mouse
						HWND hwnd = WindowFromPoint(mousepos);
						if (hwnd != NULL)
							PollWindow(rgncache, hwnd);
					}
				}

				// PROCESS THE MOUSE POINTER
				// Some of the hard work is done in clients, some here
				// This code fetches the desktop under the old pointer position
				// but the client is responsible for actually encoding and sending
				// it when required.
				// This code also renders the pointer and saves the rendered position
				// Clients include this when rendering updates.
				// The code is complicated in this way because we wish to avoid 
				// rendering parts of the screen the mouse moved through between
				// client updates, since in practice they will probably not have changed.

				// Re-render the mouse's old location if it's moved
				BOOL cursormoved = FALSE;
				POINT cursorpos;
				if (GetCursorPos(&cursorpos) && 
					((cursorpos.x != oldcursorpos.x) ||
					(cursorpos.y != oldcursorpos.y))) {
					cursormoved = TRUE;
					oldcursorpos = rfb::Point(cursorpos);
				}
				if (cursormoved) {
					if (!m_desktop->m_cursorpos.is_empty())
						rgncache = rgncache.union_(rfb::Region2D(m_desktop->m_cursorpos));
				}

				{
					// Prevent any clients from accessing the Buffer
					omni_mutex_lock l(m_desktop->m_update_lock);

					// CHECK FOR COPYRECTS
					// This actually just checks where the Foreground window is
					m_desktop->CalcCopyRects(updates);

					// GRAB THE DISPLAY
					// Fetch data from the display to our display cache.
					m_desktop->m_buffer.GrabRegion(rgncache);
				  // Render the mouse
				  m_desktop->m_buffer.GrabMouse();
					if (cursormoved) {
						// Inform clients that it has moved
						m_desktop->m_server->UpdateMouse();
						// Get the buffer to fetch the pointer bitmap
						if (!m_desktop->m_cursorpos.is_empty())
							rgncache = rgncache.union_(rfb::Region2D(m_desktop->m_cursorpos));
					}

					// SCAN THE CHANGED REGION FOR ACTUAL CHANGES
					// The hooks return hints as to areas that may have changed.
					// We check the suggested areas, and just send the ones that
					// have actually changed.
					// Note that we deliberately don't check the copyrect destination
					// here, to reduce the overhead & the likelihood of corrupting the
					// backbuffer contents.
					rfb::Region2D checkrgn = rgncache.subtract(clipped_updates.get_copied_region());
					rgncache = clipped_updates.get_copied_region();
					rfb::Region2D changedrgn;
					m_desktop->m_buffer.CheckRegion(changedrgn, checkrgn);

					// FLUSH UPDATES TO CLIENTS
					// Add the bits that have really changed to their update regions
					// Note that the cursor is NOT included - they must do that
					// themselves, for the reasons above.
					// This call implicitly kicks clients to update themselves

					updates.add_changed(changedrgn);
					clipped_updates.get_update(m_server->GetUpdateTracker());
				}

				// Clear the update tracker and region cache
				clipped_updates.clear();
			}

			// Now wait for more messages to be queued
			if (!WaitMessage()) {
				//vnclog.Print(LL_INTERR, VNCLOG("WaitMessage() failed\n"));
				break;
			}
		} else if (msg.message == RFB_SCREEN_UPDATE) {
			// Process an incoming update event

			// An area of the screen has changed
			rfb::Rect rect;
			rect.tl = rfb::Point((SHORT)LOWORD(msg.wParam), (SHORT)HIWORD(msg.wParam));
			rect.br = rfb::Point((SHORT)LOWORD(msg.lParam), (SHORT)HIWORD(msg.lParam));
			rect = rect.intersect(m_desktop->m_bmrect);
			if (!rect.is_empty()) {
				rgncache = rgncache.union_(rfb::Region2D(rect));
			}

			idle_skip = TRUE;
		} else if (msg.message == RFB_MOUSE_UPDATE) {
			// Process an incoming mouse event

			// Save the cursor ID
			m_desktop->SetCursor((HCURSOR) msg.wParam);

			idle_skip = TRUE;
		} else if (msg.message == WM_QUIT) {
			break;
		} else {
			// Process any other messages normally
			DispatchMessage(&msg);

			idle_skip = TRUE;
		}
	}

	m_desktop->SetClipboardActive(FALSE);
	
	//vnclog.Print(LL_INTINFO, VNCLOG("quitting desktop server thread\n"));

	// Clear all the hooks and close windows, etc.
	m_desktop->Shutdown();

	// Clear the shift modifier keys, now that there are no remote clients
	vncKeymap::ClearShiftKeys();

	// Switch back into our home desktop, under NT (no effect under 9x)
	vncService::SelectHDESK(home_desktop);

	return NULL;
}

// Implementation

vncDesktop::vncDesktop()
{
	m_thread = NULL;

	m_hwnd = NULL;
	m_timerid = 0;
	m_hnextviewer = NULL;
	m_hcursor = NULL;

	m_displaychanged = FALSE;
	m_update_triggered = FALSE;

	m_hrootdc = NULL;
	m_hmemdc = NULL;
	m_membitmap = NULL;

	m_initialClipBoardSeen = FALSE;

	m_foreground_window = NULL;

	// Vars for Will Dean's DIBsection patch
	m_DIBbits = NULL;
	m_formatmunged = FALSE;

	m_clipboard_active = FALSE;

	m_pollingcycle = 0;
}

vncDesktop::~vncDesktop()
{
	//vnclog.Print(LL_INTINFO, VNCLOG("killing screen server\n"));

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
}

// Tell the desktop hooks to grab & update a particular rectangle
void
vncDesktop::QueueRect(const rfb::Rect &rect)
{
	ULONG vwParam = MAKELONG(rect.tl.x, rect.tl.y);
	ULONG vlParam = MAKELONG(rect.br.x, rect.br.y);

	PostMessage(Window(), RFB_SCREEN_UPDATE, vwParam, vlParam);
}
	
// Kick the desktop hooks to perform an update
void
vncDesktop::TriggerUpdate()
{
	// Note that we should really lock the update lock here,
	// but there are periodic timer updates anyway, so
	// we don't actually need to.  Something to think about.
	if (!m_update_triggered) {
		m_update_triggered = TRUE;
		PostMessage(Window(), WM_TIMER, 0, 0);
	}
}

// Routine to startup and install all the hooks and stuff
BOOL
vncDesktop::Startup()
{


	KillScreenSaver();

	if (!InitDesktop())
		return FALSE;

	if (!InitBitmap())
		return FALSE;

	if (!ThunkBitmapInfo())
		return FALSE;

	EnableOptimisedBlits();

	if (!SetPixFormat())
		return FALSE;

    if (!SetPixShifts())
		return FALSE;

	if (!SetPalette())
		return FALSE;

	if (!InitWindow())
		return FALSE;

	// Add the system hook
/*
if (!SetHooks(
		GetCurrentThreadId(),
		RFB_SCREEN_UPDATE,
		RFB_COPYRECT_UPDATE,
		RFB_MOUSE_UPDATE
		))
	{
		//vnclog.Print(LL_INTERR, VNCLOG("failed to set system hooks\n"));
		// Switch on full screen polling, so they can see something, at least...
		m_server->PollFullScreen(TRUE);
	} else {
		//vnclog.Print(LL_INTERR, VNCLOG("set hooks OK\n"));
	}

	// Start up the keyboard and mouse filters
	SetKeyboardFilterHook(m_server->LocalInputsDisabled());
	SetMouseFilterHook(m_server->LocalInputsDisabled());
*/
    m_server->PollFullScreen(TRUE);

	// Start a timer to handle Polling Mode.  The timer will cause
	// an "idle" event once every quarter second, which is necessary if Polling
	// Mode is being used, to cause TriggerUpdate to be called.
	m_timerid = SetTimer(m_hwnd, 1, 250, NULL);

	// Initialise the buffer object
	m_buffer.SetDesktop(this);

	// Create the quarter-screen rectangle for polling
	m_qtrscreen = rfb::Rect(0, 0, m_bmrect.br.x, m_bmrect.br.y/4);

	// Everything is ok, so return TRUE
	return TRUE;
}

// Routine to shutdown all the hooks and stuff
BOOL
vncDesktop::Shutdown()
{
	// If we created a timer then kill it
	if (m_timerid != NULL)
		KillTimer(NULL, m_timerid);

	// If we created a window then kill it and the hooks
	if(m_hwnd != NULL)
	{	
		// Remove the system hooks
		//UnSetHooks(GetCurrentThreadId());

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
		//if(ReleaseDC(NULL, m_hrootdc) == 0)
		//{
		//	//vnclog.Print(LL_INTERR, VNCLOG("failed to ReleaseDC\n"));
		//}
		m_hrootdc = NULL;
	}
	if (m_hmemdc != NULL)
	{
		// Release our device context
		////if (!DeleteDC(m_hmemdc))
		//{
		//	//vnclog.Print(LL_INTERR, VNCLOG("failed to DeleteDC\n"));
		//}
		m_hmemdc = NULL;
	}
	if (m_membitmap != NULL)
	{
		// Release the custom bitmap, if any
		//if (!DeleteObject(m_membitmap))
		//{
		//	//vnclog.Print(LL_INTERR, VNCLOG("failed to DeleteObject\n"));
		//}
		m_membitmap = NULL;
	}

	// ***
	// vncService::SelectHomeWinStation();

	return TRUE;
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

	//vnclog.Print(LL_INTINFO, VNCLOG("KillScreenSaver...\n"));

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
				//vnclog.Print(LL_INTINFO, VNCLOG("Killing ScreenSaver\n"));

				// Close all windows on the screen saver desktop
				EnumDesktopWindows(hDesk, (WNDENUMPROC) &KillScreenSaverFunc, 0);
				CloseDesktop(hDesk);
				// Pause long enough for the screen-saver to close
				//Sleep(2000);
				// Reset the screen saver so it can run again
				SystemParametersInfo(SPI_SETSCREENSAVEACTIVE, TRUE, 0, SPIF_SENDWININICHANGE); 
			}// else {
			//	//vnclog.Print(LL_INTINFO, VNCLOG("Could not aquire read/write access to the desktop\n"));
			//}
			break;
		}
	}
}

BOOL
vncDesktop::InitBitmap()
{
	// Get the device context for the whole screen and find it's size
	m_hrootdc = ::GetDC(NULL);
	if (m_hrootdc == NULL) {
		//vnclog.Print(LL_INTERR, VNCLOG("failed to get display context\n"));
		return FALSE;
	}

	m_bmrect = rfb::Rect(0, 0,
		GetDeviceCaps(m_hrootdc, HORZRES),
		GetDeviceCaps(m_hrootdc, VERTRES));
	//vnclog.Print(LL_INTINFO, VNCLOG("bitmap dimensions are %d x %d\n"), m_bmrect.br.x, m_bmrect.br.y);

	// Create a compatible memory DC
	m_hmemdc = CreateCompatibleDC(m_hrootdc);
	if (m_hmemdc == NULL) {
		//vnclog.Print(LL_INTERR, VNCLOG("failed to create compatibleDC(%d)\n"), GetLastError());
		return FALSE;
	}

	// Check that the device capabilities are ok
	if ((GetDeviceCaps(m_hrootdc, RASTERCAPS) & RC_BITBLT) == 0)
	{
		MessageBox(
			NULL,
			"vncDesktop : root device doesn't support BitBlt\n"
			"WinVNC cannot be used with this graphic device driver",
			szAppName,
			MB_ICONSTOP | MB_OK
			);
		return FALSE;
	}
	if ((GetDeviceCaps(m_hmemdc, RASTERCAPS) & RC_DI_BITMAP) == 0)
	{
		MessageBox(
			NULL,
			"vncDesktop : memory device doesn't support GetDIBits\n"
			"WinVNC cannot be used with this graphics device driver",
			szAppName,
			MB_ICONSTOP | MB_OK
			);
		return FALSE;
	}

	// Create the bitmap to be compatible with the ROOT DC!!!
	m_membitmap = CreateCompatibleBitmap(m_hrootdc, m_bmrect.br.x, m_bmrect.br.y);
	if (m_membitmap == NULL) {
		//vnclog.Print(LL_INTERR, VNCLOG("failed to create memory bitmap(%d)\n"), GetLastError());
		return FALSE;
	}
	//vnclog.Print(LL_INTINFO, VNCLOG("created memory bitmap\n"));

	// Get the bitmap's format and colour details
	int result;
	memset(&m_bminfo, 0, sizeof(m_bminfo));
	m_bminfo.bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	m_bminfo.bmi.bmiHeader.biBitCount = 0;
	result = ::GetDIBits(m_hmemdc, m_membitmap, 0, 1, NULL, &m_bminfo.bmi, DIB_RGB_COLORS);
	if (result == 0) {
		//vnclog.Print(LL_INTERR, VNCLOG("unable to get display format\n"));
		return FALSE;
	}
	result = ::GetDIBits(m_hmemdc, m_membitmap,  0, 1, NULL, &m_bminfo.bmi, DIB_RGB_COLORS);
	if (result == 0) {
		//vnclog.Print(LL_INTERR, VNCLOG("unable to get display colour info\n"));
		return FALSE;
	}
	//vnclog.Print(LL_INTINFO, VNCLOG("got bitmap format\n"));

  // Henceforth we want to use a top-down scanning representation
	m_bminfo.bmi.bmiHeader.biHeight = - abs(m_bminfo.bmi.bmiHeader.biHeight);

	// Is the bitmap palette-based or truecolour?
	m_bminfo.truecolour = (GetDeviceCaps(m_hmemdc, RASTERCAPS) & RC_PALETTE) == 0;

	return TRUE;
}

BOOL
vncDesktop::ThunkBitmapInfo()
{
	// If we leave the pixel format intact, the blist can be optimised (Will Dean's patch)
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
		//vnclog.Print(LL_INTINFO, VNCLOG("DBG:used/bits/planes/comp/size = %d/%d/%d/%d/%d\n"),
		///	(int)m_bminfo.bmi.bmiHeader.biClrUsed,
		//	(int)m_bminfo.bmi.bmiHeader.biBitCount,
		//	(int)m_bminfo.bmi.bmiHeader.biPlanes,
		////	(int)m_bminfo.bmi.bmiHeader.biCompression,
		//	(int)m_bminfo.bmi.bmiHeader.biSizeImage);
		
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
  // If we are using a memory bitmap then check how many planes it uses
  // The VNC code can only handle formats with a single plane (CHUNKY pixels)
  if (!m_DIBbits) {
	  //vnclog.Print(LL_INTINFO, VNCLOG("DBG:display context has %d planes!\n"),
      //GetDeviceCaps(m_hrootdc, PLANES));
	  //vnclog.Print(LL_INTINFO, VNCLOG("DBG:memory context has %d planes!\n"),
      //GetDeviceCaps(m_hmemdc, PLANES));
	  if (GetDeviceCaps(m_hmemdc, PLANES) != 1)
	  {
		  MessageBox(
			  NULL,
			  "vncDesktop : current display is PLANAR, not CHUNKY!\n"
			  "WinVNC cannot be used with this graphics device driver",
			  szAppName,
			  MB_ICONSTOP | MB_OK
			  );
		  return FALSE;
	  }
  }

	// Examine the bitmapinfo structure to obtain the current pixel format
	m_scrinfo.format.trueColour = m_bminfo.truecolour;
	m_scrinfo.format.bigEndian = 0;

	// Set up the native buffer width, height and format
	m_scrinfo.framebufferWidth = (CARD16) (m_bmrect.br.x - m_bmrect.tl.x);		// Swap endian before actually sending
	m_scrinfo.framebufferHeight = (CARD16) (m_bmrect.br.y - m_bmrect.tl.y);	// Swap endian before actually sending
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
		// Standard 16-bit display
		if (m_bminfo.bmi.bmiHeader.biCompression == BI_RGB)
		{
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
		if (m_bminfo.bmi.bmiHeader.biCompression == BI_RGB)
		{
			redMask = 0xff0000; greenMask = 0xff00; blueMask = 0x00ff;
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
			//vnclog.Print(LL_INTERR, "unsupported truecolour pixel format for setpixshifts\n");
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
    if (!m_DIBbits) {
      // - Handle the palette for a non DIB-Section

		  LOGPALETTE *palette;
		  UINT size = sizeof(LOGPALETTE) + (sizeof(PALETTEENTRY) * 256);

		  palette = (LOGPALETTE *) new char[size];
		  if (palette == NULL) {
			  //vnclog.Print(LL_INTERR, VNCLOG("unable to allocate logical palette\n"));
			  return FALSE;
		  }

		  // Initialise the structure
		  palette->palVersion = 0x300;
		  palette->palNumEntries = 256;

		  // Get the system colours
		  if (GetSystemPaletteEntries(m_hrootdc,
			  0, 256, palette->palPalEntry) == 0)
		  {
			  //vnclog.Print(LL_INTERR, VNCLOG("unable to get system palette entries\n"));
			  delete [] palette;
			  return FALSE;
		  }

		  // Create a palette from those
		  HPALETTE pal = CreatePalette(palette);
		  if (pal == NULL)
		  {
			  //vnclog.Print(LL_INTERR, VNCLOG("unable to create HPALETTE\n"));
			  delete [] palette;
			  return FALSE;
		  }

		  // Select the palette into our memory DC
		  HPALETTE oldpalette = SelectPalette(m_hmemdc, pal, FALSE);
		  if (oldpalette == NULL)
		  {
			  //vnclog.Print(LL_INTERR, VNCLOG("unable to select() HPALETTE\n"));
			  delete [] palette;
			  DeleteObject(pal);
			  return FALSE;
		  }

		  // Worked, so realise the palette
		  //if (RealizePalette(m_hmemdc) == GDI_ERROR)
			  //vnclog.Print(LL_INTWARN, VNCLOG("warning - failed to RealizePalette\n"));

		  // It worked!
		  delete [] palette;
		  DeleteObject(oldpalette);

		  //vnclog.Print(LL_INTINFO, VNCLOG("initialised palette OK\n"));
		  return TRUE;

    } else {
      // - Handle a DIB-Section's palette

      // - Fetch the system palette for the framebuffer
      PALETTEENTRY syspalette[256];
      UINT entries = ::GetSystemPaletteEntries(m_hrootdc, 0, 256, syspalette);
      //vnclog.Print(LL_INTERR, VNCLOG("framebuffer has %u palette entries"), entries);

      // - Store it and convert it to RGBQUAD format
      RGBQUAD dibpalette[256];
      unsigned int i;
      for (i=0;i<entries;i++) {
        dibpalette[i].rgbRed = syspalette[i].peRed;
        dibpalette[i].rgbGreen = syspalette[i].peGreen;
        dibpalette[i].rgbBlue = syspalette[i].peBlue;
        dibpalette[i].rgbReserved = 0;
      }

      // - Set the rest of the palette to something nasty but usable
      for (i=entries;i<256;i++) {
        dibpalette[i].rgbRed = i % 2 ? 255 : 0;
        dibpalette[i].rgbGreen = i/2 % 2 ? 255 : 0;
        dibpalette[i].rgbBlue = i/4 % 2 ? 255 : 0;
        dibpalette[i].rgbReserved = 0;
      }

      // - Update the DIB section to use the same palette
      HDC bitmapDC=::CreateCompatibleDC(m_hrootdc);
      if (!bitmapDC) {
        //vnclog.Print(LL_INTERR, VNCLOG("unable to create temporary DC"), GetLastError());
        return FALSE;
      }
      HBITMAP old_bitmap = (HBITMAP)::SelectObject(bitmapDC, m_membitmap);
      if (!old_bitmap) {
        //vnclog.Print(LL_INTERR, VNCLOG("unable to select DIB section into temporary DC"), GetLastError());
        return FALSE;
      }
      UINT entries_set = ::SetDIBColorTable(bitmapDC, 0, 256, dibpalette);
      if (entries_set == 0) {
        //vnclog.Print(LL_INTERR, VNCLOG("unable to set DIB section palette"), GetLastError());
        return FALSE;
      }
      if (!::SelectObject(bitmapDC, old_bitmap)) {
        //vnclog.Print(LL_INTERR, VNCLOG("unable to restore temporary DC bitmap"), GetLastError());
        return FALSE;
      }
    }

  }

	// Not a palette based local screen - forget it!
	//vnclog.Print(LL_INTERR, VNCLOG("no palette data for truecolour display\n"));
	return TRUE;
}

LRESULT CALLBACK DesktopWndProc(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam);

ATOM m_wndClass = 0;

BOOL
vncDesktop::InitWindow()
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
		if (!m_wndClass) {
			//vnclog.Print(LL_INTERR, VNCLOG("failed to register window class\n"));
			return FALSE;
		}
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
		//vnclog.Print(LL_INTERR, VNCLOG("failed to create hook window\n"));
		return FALSE;
	}

	// Set the "this" pointer for the window
	SetWindowLong(m_hwnd, GWL_USERDATA, (long)this);

	// Enable clipboard hooking
	m_hnextviewer = SetClipboardViewer(m_hwnd);

	return TRUE;
}

void
vncDesktop::EnableOptimisedBlits()
{
	//vnclog.Print(LL_INTINFO, VNCLOG("attempting to enable DIBsection blits\n"));

  // *** not necessary?
  /*
	if (m_formatmunged) {
		//vnclog.Print(LL_INTINFO, VNCLOG("unable to enable fast blits\n"));
		m_DIBbits = NULL;
		return;
	}
  */

/*
	// Prepare the bitmapinfo palette if necessary (*** DOESN'T QUITE WORK!)
	if (!m_bminfo.truecolour) {
		LOGPALETTE *palette;
		UINT size = sizeof(LOGPALETTE) + (sizeof(PALETTEENTRY) * 256);

		palette = (LOGPALETTE *) new char[size];
		if (palette == NULL) {
			//vnclog.Print(LL_INTERR, VNCLOG("failed to create temp fast palette - disabling fast blits\n"));
			return;
		}

		// Initialise the structure
		palette->palVersion = 0x300;
		palette->palNumEntries = 256;

		// Get the system colours
		if (GetSystemPaletteEntries(m_hrootdc,
			0, 256, palette->palPalEntry) == 0) {
			delete [] palette;
			//vnclog.Print(LL_INTERR, VNCLOG("failed to init fast palette - disabling fast blits\n"));
			return;
		}

		// Copy the system palette into the bitmap info
		for (int i=0; i<256; i++) {
			m_bminfo.bmi.bmiColors[i].rgbReserved = 0;
			m_bminfo.bmi.bmiColors[i].rgbRed = palette->palPalEntry[i].peRed;
			m_bminfo.bmi.bmiColors[i].rgbGreen = palette->palPalEntry[i].peGreen;
			m_bminfo.bmi.bmiColors[i].rgbBlue = palette->palPalEntry[i].peBlue;
		}

		// It worked!
		delete [] palette;

		//vnclog.Print(LL_INTINFO, VNCLOG("initialised fast palette OK\n"));
	}
*/

	// Create a new DIB section
	HBITMAP tempbitmap = CreateDIBSection(m_hmemdc, &m_bminfo.bmi, DIB_RGB_COLORS, &m_DIBbits, NULL, 0);
	if (tempbitmap == NULL) {
		//vnclog.Print(LL_INTINFO, VNCLOG("failed to build DIB section - reverting to slow blits\n"));
		m_DIBbits = NULL;
		return;
	}

	// Delete the old memory bitmap
	if (m_membitmap != NULL) {
		DeleteObject(m_membitmap);
		m_membitmap = NULL;
	}

	// Replace old membitmap with DIB section
	m_membitmap = tempbitmap;

	//vnclog.Print(LL_INTINFO, VNCLOG("enabled fast DIBsection blits OK\n"));
}

BOOL
vncDesktop::Init(vncServer *server)
{
	//vnclog.Print(LL_INTINFO, VNCLOG("initialising desktop handler\n"));

	// Save the server pointer
	m_server = server;

	// Load in the arrow cursor
	m_hdefcursor = LoadCursor(NULL, IDC_ARROW);
	m_hcursor = m_hdefcursor;

	// Spawn a thread to handle that window's message queue
	vncDesktopThread *thread = new vncDesktopThread;
	if (thread == NULL) {
		//vnclog.Print(LL_INTERR, VNCLOG("failed to start hook thread\n"));
		return FALSE;
	}
	m_thread = thread;
	return thread->Init(this, m_server);
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
void
vncDesktop::CaptureScreen(const rfb::Rect &rect, BYTE *scrBuff, UINT scrBuffSize)
{
	assert(rect.enclosed_by(m_bmrect));

	// Select the memory bitmap into the memory DC
	HBITMAP oldbitmap;
	if ((oldbitmap = (HBITMAP) SelectObject(m_hmemdc, m_membitmap)) == NULL)
		return;

	// Capture screen into bitmap
	BOOL blitok = BitBlt(m_hmemdc, rect.tl.x, rect.tl.y,
		(rect.br.x-rect.tl.x),
		(rect.br.y-rect.tl.y),
		m_hrootdc, rect.tl.x, rect.tl.y, SRCCOPY);

	// Select the old bitmap back into the memory DC
	SelectObject(m_hmemdc, oldbitmap);

	if (blitok) {
		// Copy the new data to the screen buffer (CopyToBuffer optimises this if possible)
		CopyToBuffer(rect, scrBuff, scrBuffSize);
	}

}

// Add the mouse pointer to the buffer
void
vncDesktop::CaptureMouse(BYTE *scrBuff, UINT scrBuffSize)
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

	// Select the memory bitmap into the memory DC
	HBITMAP oldbitmap;
	if ((oldbitmap = (HBITMAP) SelectObject(m_hmemdc, m_membitmap)) == NULL)
		return;

	// Draw the cursor
	DrawIconEx(
		m_hmemdc,									// handle to device context 
		CursorPos.x, CursorPos.y,
		m_hcursor,									// handle to icon to draw 
		0,0,										// width of the icon 
		0,											// index of frame in animated cursor 
		NULL,										// handle to background brush 
		DI_NORMAL | DI_COMPAT						// icon-drawing flags 
		);

	// Select the old bitmap back into the memory DC
	SelectObject(m_hmemdc, oldbitmap);

	// Save the bounding rectangle
	m_cursorpos.tl = CursorPos;
	m_cursorpos.br = rfb::Point(GetSystemMetrics(SM_CXCURSOR),
		GetSystemMetrics(SM_CYCURSOR)).translate(CursorPos);

	// Clip the bounding rect to the screen
	// Copy the mouse cursor into the screen buffer, if any of it is visible
	m_cursorpos = m_cursorpos.intersect(m_bmrect);
	if (!m_cursorpos.is_empty()) {
		CopyToBuffer(m_cursorpos, scrBuff, scrBuffSize);
	}
}

// Return the current mouse pointer position
rfb::Rect
vncDesktop::MouseRect()
{
	return m_cursorpos;
}

void
vncDesktop::SetCursor(HCURSOR cursor)
{
	if (cursor == NULL)
		m_hcursor = m_hdefcursor;
	else
		m_hcursor = cursor;
}

// Manipulation of the clipboard
void vncDesktop::SetClipText(char* rfbStr)
{
  int len = strlen(rfbStr);
  char* winStr = new char[len*2+1];

  int j = 0;
  for (int i = 0; i < len; i++)
  {
    if (rfbStr[i] == 10)
      winStr[j++] = 13;
    winStr[j++] = rfbStr[i];
  }
  winStr[j++] = 0;

  // Open the system clipboard
  if (OpenClipboard(m_hwnd))
  {
    // Empty it
    if (EmptyClipboard())
    {
      HANDLE hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, j);

      if (hMem != NULL)
      {
        LPSTR pMem = (char*)GlobalLock(hMem);

        // Get the data
        strcpy(pMem, winStr);

        // Tell the clipboard
        GlobalUnlock(hMem);
        SetClipboardData(CF_TEXT, hMem);
      }
    }
  }

  delete [] winStr;

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
void
vncDesktop::CopyToBuffer(const rfb::Rect &rect, BYTE *destbuff, UINT destbuffsize)
{
	// Finish drawing anything in this thread 
	// Wish we could do this for the whole system - maybe we should
	// do something with LockWindowUpdate here.
	GdiFlush();

	// Are we being asked to blit from the DIBsection to itself?
	if (destbuff == m_DIBbits) {
		// Yes.  Ignore the request!
		return;
	}

	int y_inv;
	BYTE * destbuffpos;

	// Calculate the scanline-ordered y position to copy from
	y_inv = m_scrinfo.framebufferHeight-rect.tl.y-(rect.br.y-rect.tl.y);

	// Calculate where in the output buffer to put the data
	destbuffpos = destbuff + (m_bytesPerRow * rect.tl.y);

	// Set the number of bytes for GetDIBits to actually write
	// NOTE : GetDIBits pads the destination buffer if biSizeImage < no. of bytes required
	m_bminfo.bmi.bmiHeader.biSizeImage = (rect.br.y-rect.tl.y) * m_bytesPerRow;

	// Get the actual bits from the bitmap into the bit buffer
	// If fast (DIBsection) blits are disabled then use the old GetDIBits technique
	if (m_DIBbits == NULL) {
		if (GetDIBits(m_hmemdc, m_membitmap, y_inv,
					(rect.br.y-rect.tl.y), destbuffpos,
					&m_bminfo.bmi, DIB_RGB_COLORS) == 0)
		{
			_RPT1(_CRT_WARN, "vncDesktop : [1] GetDIBits failed! %d\n", GetLastError());
			_RPT3(_CRT_WARN, "vncDesktop : thread = %d, DC = %d, bitmap = %d\n", omni_thread::self(), m_hmemdc, m_membitmap);
			_RPT2(_CRT_WARN, "vncDesktop : y = %d, height = %d\n", y_inv, (rect.br.y-rect.tl.y));
		}
	} else {
		// Fast blits are enabled.  [I have a sneaking suspicion this will never get used, unless
		// something weird goes wrong in the code.  It's here to keep the function general, though!]

		int bytesPerPixel = m_scrinfo.format.bitsPerPixel / 8;
		BYTE *srcbuffpos = (BYTE*)m_DIBbits;

		srcbuffpos += (m_bytesPerRow * rect.tl.y) + (bytesPerPixel * rect.tl.x);
		destbuffpos += bytesPerPixel * rect.tl.x;

		int widthBytes = (rect.br.x-rect.tl.x) * bytesPerPixel;

		for(int y = rect.tl.y; y < rect.br.y; y++)
		{
			memcpy(destbuffpos, srcbuffpos, widthBytes);
			srcbuffpos += m_bytesPerRow;
			destbuffpos += m_bytesPerRow;
		}
	}
}

// Routine to find out which windows have moved
// If copyrect detection isn't perfect then this call returns
// the copyrect destination region, to allow the caller to check
// for mistakes
void
vncDesktop::CalcCopyRects(rfb::UpdateTracker &tracker)
{
	HWND foreground = GetForegroundWindow();
	RECT foreground_rect;

	// Actually, we just compare the new and old foreground window & its position
	if (foreground != m_foreground_window) {
		m_foreground_window=foreground;
		// Is the window invisible or can we not get its rect?
		if (!IsWindowVisible(foreground) ||
			!GetWindowRect(foreground, &foreground_rect)) {
			m_foreground_window_rect.clear();
		} else {
			m_foreground_window_rect = foreground_rect;
		}
	} else {
		// Same window is in the foreground - let's see if it's moved
		RECT destrect;
		rfb::Rect dest;
		rfb::Point source;

		// Get the window rectangle
		if (IsWindowVisible(foreground) && GetWindowRect(foreground, &destrect))
		{
			rfb::Rect old_foreground_window_rect = m_foreground_window_rect;
			source = m_foreground_window_rect.tl;
			m_foreground_window_rect = dest = destrect;
			if (!dest.is_empty() && !old_foreground_window_rect.is_empty())
			{
				// Got the destination position.  Now send to clients!
				if (!source.equals(dest.tl))
				{
					rfb::Point delta = rfb::Point(dest.tl.x-source.x, dest.tl.y-source.y);

					// Clip the destination rectangle
					dest = dest.intersect(m_bmrect);
					if (dest.is_empty()) return;

					// Clip the source rectangle
					dest = dest.translate(delta.negate()).intersect(m_bmrect);
					dest = dest.translate(delta);
					if (!dest.is_empty()) {
						// Tell the buffer about the copyrect
						m_buffer.CopyRect(dest, delta);

						// Notify all clients of the copyrect
						tracker.add_copied(dest, delta);
					}
				}
			}
		} else {
			m_foreground_window_rect.clear();
		}
	}
}

// Window procedure for the Desktop window
LRESULT CALLBACK
DesktopWndProc(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	vncDesktop *_this = (vncDesktop*)GetWindowLong(hwnd, GWL_USERDATA);

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
				int cliplen = strlen(cliptext);
				LPSTR unixtext = (char *)malloc(cliplen+1);

				// Replace CR-LF with LF - never send CR-LF on the wire,
				// since Unix won't like it
				int unixpos=0;
				for (int x=0; x<cliplen; x++)
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
