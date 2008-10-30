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


// vncDesktop object

// The vncDesktop object handles retrieval of data from the
// display buffer.  It also uses the RFBLib DLL to supply
// information on mouse movements and screen updates to
// the server

class vncDesktop;

#if !defined(_WINVNC_VNCDESKTOP)
#define _WINVNC_VNCDESKTOP
#pragma once

// Include files
#include "stdhdrs.h"

class vncServer;
#include "rfbRegion.h"
#include "rfbUpdateTracker.h"
#include "vncBuffer.h"
#include "translate.h"
#include <omnithread.h>

// Constants
extern const UINT RFB_SCREEN_UPDATE;
extern const UINT RFB_COPYRECT_UPDATE;
extern const UINT RFB_MOUSE_UPDATE;
extern const char szDesktopSink[];

// Class definition

class vncDesktop
{

// Fields
public:

// Methods
public:
	// Make the desktop thread & window proc friends
	friend class vncDesktopThread;
	friend LRESULT CALLBACK DesktopWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

	// Create/Destroy methods
	vncDesktop();
	~vncDesktop();

	BOOL Init(vncServer *pSrv);

	// Tell the desktop hooks to grab & update a particular rectangle
	void QueueRect(const rfb::Rect &rect);
	
	// Kick the desktop hooks to perform an update
	void TriggerUpdate();

	// Get a reference to the desktop update lock
	// The lock is held while data is being grabbed and copied
	// to the back buffer, and while changes are being passed to
	// clients
	omni_mutex &GetUpdateLock() {return m_update_lock;};

	// Screen translation, capture, info
	void FillDisplayInfo(rfbServerInitMsg *scrInfo);
	void CaptureScreen(const rfb::Rect &UpdateArea, BYTE *scrBuff, UINT scrBuffSize);
	int ScreenBuffSize();
	HWND Window() {return m_hwnd;};

	// Mouse related
	void CaptureMouse(BYTE *scrBuff, UINT scrBuffSize);
	rfb::Rect MouseRect();
	void SetCursor(HCURSOR cursor);

	// Clipboard manipulation
	void SetClipText(LPSTR text);

	// Method to obtain the DIBsection buffer if fast blits are enabled
	// If they're disabled, it'll return NULL
	inline VOID *OptimisedBlitBuffer() {return m_DIBbits;};

	BOOL	m_initialClipBoardSeen;

	// Handler for pixel data grabbing and region change checking
	vncBuffer		m_buffer;

	// Implementation
protected:

	// Routines to hook and unhook us
	BOOL Startup();
	BOOL Shutdown();
	
	// Init routines called by the child thread
	BOOL InitDesktop();
	void KillScreenSaver();
	void KillWallpaper();
	void RestoreWallpaper();
	BOOL InitBitmap();
	BOOL InitWindow();
	BOOL ThunkBitmapInfo();
	BOOL SetPixFormat();
	BOOL SetPixShifts();
	BOOL InitHooks();
	BOOL SetPalette();

	// Fetching pixel data to a buffer, and handling copyrects
	void CopyToBuffer(const rfb::Rect &rect, BYTE *scrBuff, UINT scrBuffSize);
	void CalcCopyRects(rfb::UpdateTracker &tracker);

	// Routine to attempt enabling optimised DIBsection blits
	void EnableOptimisedBlits();

	// Convert a bit mask eg. 00111000 to max=7, shift=3
	static void MaskToMaxAndShift(DWORD mask, CARD16 &max, CARD8 &shift);
	
	// Enabling & disabling clipboard handling
	void SetClipboardActive(BOOL active) {m_clipboard_active = active;};

	// DATA

	// Generally useful stuff
	vncServer 		*m_server;
	omni_thread 	*m_thread;
	HWND			m_hwnd;
	UINT			m_timerid;
	HWND			m_hnextviewer;
	BOOL			m_clipboard_active;

	// device contexts for memory and the screen
	HDC				m_hmemdc;
	HDC				m_hrootdc;

	// New and old bitmaps
	HBITMAP			m_membitmap;
	omni_mutex		m_update_lock;

	rfb::Rect		m_bmrect;
	struct _BMInfo {
		BOOL			truecolour;
		BITMAPINFO		bmi;
		// Colormap info - comes straight after BITMAPINFO - **HACK**
		RGBQUAD			cmap[256];
	} m_bminfo;

	// Screen info
	rfbServerInitMsg	m_scrinfo;

	// These are the red, green & blue masks for a pixel
	DWORD			m_rMask, m_gMask, m_bMask;

	// This is always handy to have
	int				m_bytesPerRow;

	// Handle of the default cursor
	HCURSOR			m_hcursor;
	// Handle of the basic arrow cursor
	HCURSOR			m_hdefcursor;
	// The current mouse position
	rfb::Rect		m_cursorpos;

	// Boolean flag to indicate when the display resolution has changed
	BOOL			m_displaychanged;

	// Boolean flag to indicate whether or not an update trigger message
	// is already in the desktop thread message queue
	BOOL			m_update_triggered;

	// Extra vars used for the DIBsection optimisation
	VOID			*m_DIBbits;
	BOOL			m_formatmunged;

	// Info used for polling modes
	rfb::Rect		m_qtrscreen;
	UINT			m_pollingcycle;

	// Handling of the foreground window, to produce CopyRects
	HWND			m_foreground_window;
	rfb::Rect		m_foreground_window_rect;
};

#endif // _WINVNC_VNCDESKTOP
