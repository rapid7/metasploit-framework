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

// VNCHooks.cpp : Defines the implementation of the DLL.
//

#include "VNCHooks.h"

#include <stdlib.h>
#include <stdio.h>
#include <crtdbg.h>

/////////////////////////////////////////////////////////////////////////////
// Storage for the global data in the DLL
// Note: For Borland C++ compilers, this data segment is defined in a
//       separate file, SharedData.cpp.

#ifdef _MSC_VER

// MSVC is bugged - if a default value is missed off from one of the following
// variables then that variable is process-specific for some reason!

#pragma data_seg(".SharedData")
HWND hVeneto = NULL;
HWND hKeyboardPriorityWindow = NULL;
HWND hMousePriorityWindow = NULL;
UINT UpdateRectMessage = 0;
UINT CopyRectMessage = 0;
UINT MouseMoveMessage = 0;
UINT LocalMouseMessage = 0;
UINT LocalKeyboardMessage = 0;
HHOOK hCallWndHook = NULL;							// Handle to the CallWnd hook
HHOOK hGetMsgHook = NULL;							// Handle to the GetMsg hook
HHOOK hDialogMsgHook = NULL;						// Handle to the DialogMsg hook
HHOOK hLLKeyboardHook = NULL;						// Handle to LowLevel kbd hook
HHOOK hLLMouseHook = NULL;							// Handle to LowLevel mouse hook
HHOOK hLLKeyboardPrHook = NULL;						// Handle to LowLevel kbd hook for local event priority
HHOOK hLLMousePrHook = NULL;						// Handle to LowLevel mouse hook for local event priority
HHOOK hKeyboardHook = NULL;							// Handle to kbd hook
HHOOK hMouseHook = NULL;							// Handle to mouse hook

#pragma data_seg( )

#else

#include "SharedData.h"

#endif // _MSC_VER

/////////////////////////////////////////////////////////////////////////////
// Per-instance DLL variables

const char sPrefSegment[] = "Application_Prefs\\";
char *sModulePrefs = NULL;							// Name of the module that created us
BOOL prf_use_GetUpdateRect = FALSE;					// Use the GetUpdateRect paint mode
BOOL prf_use_Timer = FALSE;							// Use Timer events to trigger updates
BOOL prf_use_KeyPress = FALSE;						// Use keyboard events
BOOL prf_use_LButtonUp = TRUE;						// Use left mouse button up events
BOOL prf_use_MButtonUp = FALSE;						// Use middle mouse button up events
BOOL prf_use_RButtonUp = FALSE;						// Use right mouse button up events
BOOL prf_use_Deferral = FALSE;						// Use deferred updates

HKEY hModuleKey = NULL;								// Key used to save settings
HINSTANCE hInstance = NULL;							// This instance of the DLL
BOOL HookMaster = FALSE;							// Is this instance veneto itself?

BOOL appHookedOK = FALSE;							// Did InitInstance succeed?

/////////////////////////////////////////////////////////////////////////////
// Registered messages & atoms to be used by VNCHooks.DLL

// Messages
const UINT VNC_DEFERRED_UPDATE = RegisterWindowMessage("VNCHooks.Deferred.UpdateMessage");

// Atoms
const char *VNC_WINDOWPOS_ATOMNAME = "VNCHooks.CopyRect.WindowPos";
const char *VNC_POPUPSELN_ATOMNAME = "VNCHooks.PopUpMenu.Selected";
ATOM VNC_WINDOWPOS_ATOM = NULL;
ATOM VNC_POPUPSELN_ATOM = NULL;

/////////////////////////////////////////////////////////////////////////////
// The DLL functions

// Forward definition of hook procedures

BOOL HookHandle(UINT msg, HWND hWnd, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK CallWndProc (int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK GetMessageProc(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK DialogMessageProc(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK LowLevelKeyboardFilterProc(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK LowLevelMouseFilterProc(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK LowLevelKeyboardPriorityProc(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK LowLevelMousePriorityProc(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK KeyboardPriorityProc(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK MousePriorityProc(int nCode, WPARAM wParam, LPARAM lParam);

// Forward definition of setup and shutdown procedures
BOOL InitInstance();
BOOL ExitInstance();

// The DLL's main procedure
BOOL WINAPI DllMain (HANDLE hInst, ULONG ul_reason_for_call, LPVOID lpReserved)
{
	// Find out why we're being called
	switch (ul_reason_for_call)
	{

	case DLL_PROCESS_ATTACH:
#ifdef _MSC_VER
		_RPT0(_CRT_WARN, "vncHooks : Hook DLL loaded\n");
#endif

		// Save the instance handle
		hInstance = (HINSTANCE)hInst;

		// Call the initialisation function
		appHookedOK = InitInstance();

		// ALWAYS return TRUE to avoid breaking unhookable applications!!!
		return TRUE;

	case DLL_PROCESS_DETACH:
#ifdef _MSC_VER
		_RPT0(_CRT_WARN, "vncHooks : Hook DLL unloaded\n");
#endif
		
		// Call the exit function
		// If the app failed to hook OK, ExitInstance will still operate OK (hopefully...)
		ExitInstance();

		return TRUE;

	default:
		return TRUE;
	}
}

// Add the new hook

DllExport BOOL SetHook(HWND hWnd, UINT UpdateMsg, UINT CopyMsg, UINT MouseMsg)
{

	// Don't add the hook if the window ID is NULL
	if (hWnd == NULL)
		return FALSE;
	
	// Don't add a hook if there is already one added
	if (hVeneto != NULL)
		return FALSE;

	// Add the CallWnd hook
	hCallWndHook = SetWindowsHookEx(
					WH_CALLWNDPROC,					// Hook in before msg reaches app
					(HOOKPROC) CallWndProc,			// Hook procedure
					hInstance,						// This DLL instance
					0L								// Hook in to all apps
//					GetCurrentThreadId()			// DEBUG : HOOK ONLY WinVNC
					);

	// Add the GetMessage hook
	hGetMsgHook = SetWindowsHookEx(
					WH_GETMESSAGE,					// Hook in before msg reaches app
					(HOOKPROC) GetMessageProc,			// Hook procedure
					hInstance,						// This DLL instance
					0L								// Hook in to all apps
//					GetCurrentThreadId()			// DEBUG : HOOK ONLY WinVNC
					);

		// Add the GetMessage hook
	hDialogMsgHook = SetWindowsHookEx(
					WH_SYSMSGFILTER,				// Hook in dialogs, menus and scrollbars
					(HOOKPROC) DialogMessageProc,	// Hook procedure
					hInstance,						// This DLL instance
					0L								// Hook in to all apps
					);

	// Check that it worked
	if ((hCallWndHook != NULL) && (hGetMsgHook != NULL) && (hDialogMsgHook != NULL))
	{
		hVeneto = hWnd;						// Save the WinRFB window handle
		UpdateRectMessage = UpdateMsg;		// Save the message ID to use for rectangle updates
		CopyRectMessage = CopyMsg;			// Save the message ID to use for copyrect
		MouseMoveMessage = MouseMsg;		// Save the message ID to send when mouse moves
		HookMaster = TRUE;					// Set the HookMaster flag for this instance
		
#ifdef _MSC_VER
		_RPT1(_CRT_WARN, "Window : %d\n", hWnd);
#endif
		
		return TRUE;
	}
	else
	{
		// Stop the keyboard hook
		SetKeyboardFilterHook(FALSE);
		SetMouseFilterHook(FALSE);

		// Kill the main hooks
		if (hCallWndHook != NULL)
			UnhookWindowsHookEx(hCallWndHook);
		if (hGetMsgHook != NULL)
			UnhookWindowsHookEx(hGetMsgHook);
		if (hDialogMsgHook != NULL)
			UnhookWindowsHookEx(hDialogMsgHook);
		hCallWndHook = NULL;
		hGetMsgHook = NULL;
		hDialogMsgHook = NULL;
	}

	// The hook failed, so return an error code
	return FALSE;

}

// EnumWindows procedure to remove the extra property we added

BOOL CALLBACK
KillPropsProc(HWND hwnd, LPARAM lParam)
{
	// Remove our custom property...
	RemoveProp(hwnd, (LPCTSTR) MAKEWORD(VNC_WINDOWPOS_ATOM, 0));
	RemoveProp(hwnd, (LPCTSTR) MAKEWORD(VNC_POPUPSELN_ATOM, 0));
	return TRUE;
}

// Remove the hook from the system

DllExport BOOL UnSetHook(HWND hWnd)
{

	BOOL unHooked = TRUE;
	
	// Remove the extra property value from all local windows
	EnumWindows((WNDENUMPROC) &KillPropsProc, NULL);

	// Stop the keyboard & mouse hooks
	unHooked = unHooked && SetKeyboardFilterHook(FALSE);
	unHooked = unHooked && SetMouseFilterHook(FALSE);

	// Is the window handle valid?
	if (hWnd == NULL)
		MessageBox(NULL, "Window pointer is null", "Message", MB_OK);

	// Is the correct application calling UnSetHook?
	if (hWnd != hVeneto)
		return FALSE;

	// Unhook the procs
	if (hCallWndHook != NULL)
	{
		unHooked = unHooked && UnhookWindowsHookEx(hCallWndHook);
		hCallWndHook = NULL;
	}

	if (hGetMsgHook != NULL)
	{
		unHooked = unHooked && UnhookWindowsHookEx(hGetMsgHook);
		hGetMsgHook = NULL;
	}

	if (hDialogMsgHook != NULL)
	{
		unHooked = unHooked && UnhookWindowsHookEx(hDialogMsgHook);
		hDialogMsgHook = NULL;
	}

	// If we managed to unhook then reset
	if (unHooked)
	{
		hVeneto = NULL;
		HookMaster = FALSE;
	}

	return unHooked;

}

// Routine to start and stop local keyboard message filtering
DllExport BOOL SetKeyboardFilterHook(BOOL activate)
{
	if (activate)
	{
#ifdef WH_KEYBOARD_LL
		if (hLLKeyboardHook == NULL)
		{
			// Start up the hook...
			hLLKeyboardHook = SetWindowsHookEx(
					WH_KEYBOARD_LL,					// Hook in before msg reaches app
					(HOOKPROC) LowLevelKeyboardFilterProc,			// Hook procedure
					hInstance,						// This DLL instance
					0L								// Hook in to all apps
					);
			if (hLLKeyboardHook == NULL)
				return FALSE;
		}
		return TRUE;
#else
#pragma message("warning:Low-Level Keyboard hook code omitted.")
		return FALSE;
#endif
	} else {
		if (hLLKeyboardHook != NULL)
		{
			// Stop the hook...
			if (!UnhookWindowsHookEx(hLLKeyboardHook))
				return FALSE;
			hLLKeyboardHook = NULL;
		}
		return TRUE;
	}
}

DllExport BOOL SetKeyboardPriorityLLHook(HWND hwnd, BOOL activate, UINT LocalKbdMsg)
{
	LocalKeyboardMessage = LocalKbdMsg;
	if (activate)
	{
#ifdef WH_KEYBOARD_LL
		if (hLLKeyboardPrHook == NULL)
		{
			// save the window handle
			hKeyboardPriorityWindow = hwnd;
		
			// Start up the hook...
			hLLKeyboardPrHook = SetWindowsHookEx(
					WH_KEYBOARD_LL,					// Hook in before msg reaches app
					(HOOKPROC) LowLevelKeyboardPriorityProc,			// Hook procedure
					hInstance,						// This DLL instance
					0L								// Hook in to all apps
					);
			if (hLLKeyboardPrHook == NULL)
				return FALSE;
		}
		return TRUE;
#else
#pragma message("warning:Low-Level Keyboard hook code omitted.")
		return FALSE;
#endif
	} else {
		if (hLLKeyboardPrHook != NULL)
		{
			// Stop the hook...
			if (!UnhookWindowsHookEx(hLLKeyboardPrHook))
				return FALSE;
				
			// reset the hook and window handle
			hKeyboardPriorityWindow = NULL;
			hLLKeyboardPrHook = NULL;
		}
		return TRUE;
	}
}

// Routine to start and stop local mouse message filtering
DllExport BOOL SetMouseFilterHook(BOOL activate)
{
	if (activate)
	{
#ifdef WH_MOUSE_LL
		if (hLLMouseHook == NULL)
		{
			// Start up the hook...
			hLLMouseHook = SetWindowsHookEx(
					WH_MOUSE_LL,					// Hook in before msg reaches app
					(HOOKPROC) LowLevelMouseFilterProc,			// Hook procedure
					hInstance,						// This DLL instance
					0L								// Hook in to all apps
					);
			if (hLLMouseHook == NULL)
				return FALSE;
		}
		return TRUE;
#else
#pragma message("warning:Low-Level Mouse hook code omitted.")
		return FALSE;
#endif
	} else {
		if (hLLMouseHook != NULL)
		{
			// Stop the hook...
			if (!UnhookWindowsHookEx(hLLMouseHook))
				return FALSE;
			hLLMouseHook = NULL;
		}
		return TRUE;
	}
}

DllExport BOOL SetMousePriorityLLHook(HWND hwnd, BOOL activate, UINT LocalMouseMsg)
{
	LocalMouseMessage = LocalMouseMsg;
	if (activate)
	{
#ifdef WH_MOUSE_LL
		if (hLLMousePrHook == NULL)
		{
			// save the window handle
			hMousePriorityWindow = hwnd;
		
			// Start up the hook...
			hLLMousePrHook = SetWindowsHookEx(
					WH_MOUSE_LL,					// Hook in before msg reaches app
					(HOOKPROC) LowLevelMousePriorityProc,			// Hook procedure
					hInstance,						// This DLL instance
					0L								// Hook in to all apps
					);
			if (hLLMousePrHook == NULL)
				return FALSE;
		}
		return TRUE;
#else
#pragma message("warning:Low-Level Mouse hook code omitted.")
		return FALSE;
#endif
	} else {
		if (hLLMousePrHook != NULL)
		{
			// Stop the hook...
			if (!UnhookWindowsHookEx(hLLMousePrHook))
				return FALSE;
				
			// reset the hook and window handle
			hMousePriorityWindow = NULL;
			hLLMousePrHook = NULL;
		}
		return TRUE;
	}
}


// Routine to start and stop local keyboard message filtering
DllExport BOOL SetKeyboardPriorityHook(HWND hwnd, BOOL activate, UINT LocalKbdMsg)
{
	LocalKeyboardMessage = LocalKbdMsg;
	if (activate)
	{
		if (hKeyboardHook == NULL)
		{
			// save the window handle
			hKeyboardPriorityWindow = hwnd;

			// Start up the hook...
			hKeyboardHook = SetWindowsHookEx(
					WH_KEYBOARD,					// Hook in before msg reaches app
					(HOOKPROC) KeyboardPriorityProc,// Hook procedure
					hInstance,						// This DLL instance
					0L								// Hook in to all apps
					);
			if (hKeyboardHook == NULL)
				return FALSE;
		}
		return TRUE;
	} else {
		if (hKeyboardHook != NULL)
		{
			// Stop the hook...
			if (!UnhookWindowsHookEx(hKeyboardHook))
				return FALSE;
			
			// reset the hook and window handle
			hKeyboardPriorityWindow = NULL;
			hKeyboardHook = NULL;
		}
		return TRUE;
	}
}


// Routine to start and stop local mouse message filtering
DllExport BOOL SetMousePriorityHook(HWND hwnd, BOOL activate, UINT LocalMouseMsg)
{
	LocalMouseMessage = LocalMouseMsg;
	if (activate)
	{
		if (hMouseHook == NULL)
		{
			// save the window handle
			hMousePriorityWindow = hwnd;
 		
			// Start up the hook...
			hMouseHook = SetWindowsHookEx(
					WH_MOUSE,					// Hook in before msg reaches app
					(HOOKPROC) MousePriorityProc,			// Hook procedure
					hInstance,						// This DLL instance
					0L								// Hook in to all apps
					);
			if (hMouseHook == NULL)
				return FALSE;
		}
		return TRUE;
	} else {
		if (hMouseHook != NULL)
		{
			// Stop the hook...
			if (!UnhookWindowsHookEx(hMouseHook))
				return FALSE;
				
			// reset the hook and window handle
			hMousePriorityWindow = NULL;
			hMouseHook = NULL;
		}
		return TRUE;
	}
}



// Routine to get the window's client rectangle, in screen coordinates
inline BOOL GetAbsoluteClientRect(HWND hwnd, RECT *rect)
{
	POINT topleft;
	topleft.x = 0;
	topleft.y = 0;

	// Get the client rectangle size
	if (!GetClientRect(hwnd, rect))
		return FALSE;

	// Get the client rectangle position
	if (!ClientToScreen(hwnd, &topleft))
		return FALSE;

	// Now adjust the window rectangle
	rect->left += topleft.x;
	rect->top += topleft.y;
	rect->right += topleft.x;
	rect->bottom += topleft.y;

	return TRUE;
}

// Routine to send a CopyRect message to WinVNC
inline void SendCopyWindowRect(HWND hWnd)
{
	WPARAM vwParam;

	// All we send back is the handle of the window to be moved
	vwParam = (LPARAM) hWnd;

	// Send the update to Veneto
	PostMessage(
		hVeneto,
		CopyRectMessage,
		vwParam,
		0
		);
}

// Routine to send an UpdateRect message to Veneto
inline void SendUpdateRect(SHORT x, SHORT y, SHORT x2, SHORT y2)
{
	WPARAM vwParam;
	LPARAM vlParam;

	vwParam = MAKELONG(x, y);
	vlParam = MAKELONG(x2, y2);

	// Send the update to Veneto
	PostMessage(
		hVeneto,
		UpdateRectMessage,
		vwParam,
		vlParam
		);
}

// Send a window's position to Veneto

inline void SendWindowRect(HWND hWnd)
{
	RECT wrect;

	// Get the rectangle position
	if (GetWindowRect(hWnd, &wrect) && IsWindowVisible(hWnd))
	{
		// Send the position
		SendUpdateRect(
			(SHORT) wrect.left,
			(SHORT) wrect.top,
			(SHORT) wrect.right,
			(SHORT) wrect.bottom
			);
	}
}

// Send a deferred message into this Window's message queue, so that
// we'll intercept it again only after the message that triggered it has been
// handled

inline void SendDeferredUpdateRect(HWND hWnd, SHORT x, SHORT y, SHORT x2, SHORT y2)
{
	WPARAM vwParam;
	LPARAM vlParam;

	vwParam = MAKELONG(x, y);
	vlParam = MAKELONG(x2, y2);

	if (prf_use_Deferral)
	{
		// Send the update back to the window
		PostMessage(
			hWnd,
			VNC_DEFERRED_UPDATE,
			vwParam,
			vlParam
			);
	}
	else
	{
		// Send the update to WinRFB
		PostMessage(
			hVeneto,
			UpdateRectMessage,
			vwParam,
			vlParam
			);
	}
}

inline void SendDeferredWindowRect(HWND hWnd)
{
	RECT wrect;

	// Get the rectangle position
	if (::GetWindowRect(hWnd, &wrect) && ::IsWindowVisible(hWnd))
	{
		// Send the position
		SendDeferredUpdateRect(
			hWnd,
			(SHORT) wrect.left,
			(SHORT) wrect.top,
			(SHORT) wrect.right,
			(SHORT) wrect.bottom
			);
	}
}

inline void SendDeferredBorderRect(HWND hWnd)
{
	RECT wrect;
	RECT crect;

	// Get the rectangle position
	if (GetWindowRect(hWnd, &wrect) && ::IsWindowVisible(hWnd))
	{
		// Get the client rectangle position
		if (GetAbsoluteClientRect(hWnd, &crect))
		{
			// Send the four border rectangles
			SendDeferredUpdateRect(hWnd, (SHORT) wrect.left, (SHORT) wrect.top, (SHORT) wrect.right, (SHORT) crect.top);
			SendDeferredUpdateRect(hWnd, (SHORT) wrect.left, (SHORT) wrect.top, (SHORT) crect.left, (SHORT) wrect.bottom);
			SendDeferredUpdateRect(hWnd, (SHORT) wrect.left, (SHORT) crect.bottom, (SHORT) wrect.right, (SHORT) wrect.bottom);
			SendDeferredUpdateRect(hWnd, (SHORT) crect.right, (SHORT) wrect.top, (SHORT) wrect.right, (SHORT) wrect.bottom);
		}
	}
}

// Generic hook-handler

inline BOOL HookHandle(UINT MessageId, HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	////////////////////////////////////////////////////////////////
	// *** HANDLE DEFERRED UPDATES ***

	// Is this a deferred-update message?
	if (MessageId == VNC_DEFERRED_UPDATE)
	{

		// NOTE : NEVER use the SendDeferred- routines to send updates
		//		from here, or you'll get an infinite loop....!

		// NB : The format of DEFERRED_UPDATE matches that of UpdateRectMessage,
		//		so just send the exact same message data to WinRFB:

		PostMessage(
			hVeneto,
			UpdateRectMessage,
			wParam,
			lParam
			);

		return FALSE;
	}

	// *** Could use WM_COPYDATA to send data to WinVNC

/*
	if (GetClassLong(hWnd, GCW_ATOM) == 32768)
	{
		_RPT4(_CRT_WARN, "DBG : popup menu message (hwnd=%d, msg=%d, l=%d, w=%d)\n",
		hWnd, MessageId, lParam, wParam);
	}
*/

	////////////////////////////////////////////////////////////////
	// *** UPDATE-TRIGGERING MESSAGES ***

	// Do something dependent upon message type
	switch (MessageId)
	{
		
		////////////////////////////////////////////////////////////////
		// Messages indicating only a border repaint.
	case WM_NCPAINT:
	case WM_NCACTIVATE:
		SendDeferredBorderRect(hWnd);
		break;

		////////////////////////////////////////////////////////////////
		// Messages indicating a client area repaint
	case WM_CHAR:
	case WM_KEYUP:							// Handle key-presses
		if (prf_use_KeyPress)
			SendDeferredWindowRect(hWnd);
		break;

	case WM_LBUTTONUP:						// Handle LMB clicks
		if (prf_use_LButtonUp)
			SendDeferredWindowRect(hWnd);
		break;

	case WM_MBUTTONUP:						// Handle MMB clicks
		if (prf_use_MButtonUp)
			SendDeferredWindowRect(hWnd);
		break;

	case WM_RBUTTONUP:						// Handle RMB clicks
		if (prf_use_RButtonUp)
			SendDeferredWindowRect(hWnd);
		break;

	case WM_TIMER:
		if (prf_use_Timer)
			SendDeferredWindowRect(hWnd);
		break;

	case WM_HSCROLL:
	case WM_VSCROLL:
		if (((int) LOWORD(wParam) == SB_THUMBTRACK) || ((int) LOWORD(wParam) == SB_ENDSCROLL))
			SendDeferredWindowRect(hWnd);
		break;

	case 485:  // HACK to handle popup menus
		{
			// Get the old popup menu selection value
			HANDLE prop = GetProp(hWnd, (LPCTSTR) MAKELONG(VNC_POPUPSELN_ATOM, 0));
			if (prop != (HANDLE) wParam)
			{
				// It did, so update the menu & the selection value
				SendDeferredWindowRect(hWnd);
				SetProp(hWnd,
					(LPCTSTR) MAKELONG(VNC_POPUPSELN_ATOM, 0),
					(HANDLE) wParam);
			}
		}
		break;

		////////////////////////////////////////////////////////////////
		// Messages indicating a full window update
	case WM_SYSCOLORCHANGE:
	case WM_PALETTECHANGED:
	case WM_SETTEXT:
	case WM_ENABLE:
	case BM_SETCHECK:
	case BM_SETSTATE:
	case EM_SETSEL:
	//case WM_MENUSELECT:
		SendDeferredWindowRect(hWnd);
		break;

		////////////////////////////////////////////////////////////////
		// Messages indicating that an area of the window needs updating
		// Uses GetUpdateRect to find out which
	case WM_PAINT:
		if (prf_use_GetUpdateRect)
		{
			HRGN region;
			region = CreateRectRgn(0, 0, 0, 0);

			// Get the affected region
			if (GetUpdateRgn(hWnd, region, FALSE) != ERROR)
			{
				int buffsize;
				UINT x;
				RGNDATA *buff;
				POINT TopLeft;

				// Get the top-left point of the client area
				TopLeft.x = 0;
				TopLeft.y = 0;
				if (!ClientToScreen(hWnd, &TopLeft))
					break;

				// Get the size of buffer required
				buffsize = GetRegionData(region, 0, 0);
				if (buffsize != 0)
				{
					buff = (RGNDATA *) new BYTE [buffsize];
					if (buff == NULL)
						break;

					// Now get the region data
					if(GetRegionData(region, buffsize, buff))
					{
						for (x=0; x<(buff->rdh.nCount); x++)
						{
							// Obtain the rectangles from the list
							RECT *urect = (RECT *) (((BYTE *) buff) + sizeof(RGNDATAHEADER) + (x * sizeof(RECT)));
							SendDeferredUpdateRect(
								hWnd,
								(SHORT) (TopLeft.x + urect->left),
								(SHORT) (TopLeft.y + urect->top),
								(SHORT) (TopLeft.x + urect->right),
								(SHORT) (TopLeft.y + urect->bottom)
								);
						}
					}

					delete [] buff;
				}
			}

			// Now free the region
			if (region != NULL)
				DeleteObject(region);
		}
		else
			SendDeferredWindowRect(hWnd);
		break;

		////////////////////////////////////////////////////////////////
		// Messages indicating full repaint of this and a different window
		// Send the new position of the window
	case WM_WINDOWPOSCHANGING:
		if (IsWindowVisible(hWnd))
			SendWindowRect(hWnd);
		break;

	case WM_WINDOWPOSCHANGED:
		if (IsWindowVisible(hWnd))
			SendDeferredWindowRect(hWnd);
		break;

		////////////////////////////////////////////////////////////////
		// WinRFB also wants to know about mouse movement
	case WM_NCMOUSEMOVE:
	case WM_MOUSEMOVE:
		// Inform WinRFB that the mouse has moved and pass it the current cursor handle
		PostMessage(
			hVeneto,
			MouseMoveMessage,
			(ULONG) GetCursor(),
			0
		);
		break;

		////////////////////////////////////////////////////////////////
		// VNCHOOKS PROPERTIES HANDLING WINDOWS
	case WM_DESTROY:
		RemoveProp(hWnd, (LPCTSTR) MAKEWORD(VNC_WINDOWPOS_ATOM, 0));
		RemoveProp(hWnd, (LPCTSTR) MAKEWORD(VNC_POPUPSELN_ATOM, 0));
		break;

	}

	return TRUE;
}

// Hook procedure for CallWindow hook

LRESULT CALLBACK CallWndProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	// Do we have to handle this message?
	if (nCode == HC_ACTION)
	{
		// Process the hook if the Veneto window handle is valid
		if (hVeneto != NULL)
		{
			CWPSTRUCT *cwpStruct = (CWPSTRUCT *) lParam;
			HookHandle(cwpStruct->message, cwpStruct->hwnd, cwpStruct->wParam, cwpStruct->lParam);
		}
	}

	// Call the next handler in the chain
    return CallNextHookEx (hCallWndHook, nCode, wParam, lParam);
}

// Hook procedure for GetMessageProc hook

LRESULT CALLBACK GetMessageProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	// Do we have to handle this message?
	if (nCode == HC_ACTION)
	{
		// Process the hook only if the Veneto window is valid
		if (hVeneto != NULL)
		{
			MSG *msg = (MSG *) lParam;

			// Only handle application messages if they're being removed:
			if (wParam & PM_REMOVE)
			{
				// Handle the message
				HookHandle(msg->message, msg->hwnd, msg->wParam, msg->lParam);
			}
		}
	}

	// Call the next handler in the chain
    return CallNextHookEx (hGetMsgHook, nCode, wParam, lParam);
}

// Hook procedure for DialogMessageProc hook

LRESULT CALLBACK DialogMessageProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	// Do we have to handle this message?
	if (nCode >= 0)
	{
		// Process the hook only if the Veneto window is valid
		if (hVeneto != NULL)
		{
			MSG *msg = (MSG *) lParam;

			// Handle the message
			HookHandle(msg->message, msg->hwnd, msg->wParam, msg->lParam);
		}
	}

	// Call the next handler in the chain
    return CallNextHookEx (hGetMsgHook, nCode, wParam, lParam);
}

// Hook procedure for LowLevel Keyboard filtering

#ifdef WH_KEYBOARD_LL
LRESULT CALLBACK LowLevelKeyboardFilterProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	// Are we expected to handle this callback?
	if (nCode == HC_ACTION)
	{
		// Is this keyboard event "real" or "injected"
		// i.e. hardware or software-produced?
		KBDLLHOOKSTRUCT *hookStruct = (KBDLLHOOKSTRUCT*)lParam;
		if (!(hookStruct->flags & LLKHF_INJECTED)) {
			// Message was not injected - reject it!
			return TRUE;
		}
	}

	// Otherwise, pass on the message
	return CallNextHookEx(hLLKeyboardHook, nCode, wParam, lParam);
}

LRESULT CALLBACK LowLevelKeyboardPriorityProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	// Are we expected to handle this callback?
	// do we have a target window handle?
	if (nCode == HC_ACTION && hKeyboardPriorityWindow != NULL)
	{
		// Is this keyboard event "real" or "injected"
		// i.e. hardware or software-produced?
		KBDLLHOOKSTRUCT *hookStruct = (KBDLLHOOKSTRUCT*)lParam;
		if (!(hookStruct->flags & LLKHF_INJECTED)) {
			// Message was not injected - send RFB_LOCAL_KEYBOARD msg!
			// Remote event will be blocked
			PostMessage(
				hKeyboardPriorityWindow,
				LocalKeyboardMessage,
				0,
				0
				);
		}
	}

	// Otherwise, pass on the message
	return CallNextHookEx(hLLKeyboardPrHook, nCode, wParam, lParam);
}

#endif

// Hook procedure for LowLevel Mouse filtering

#ifdef WH_MOUSE_LL
LRESULT CALLBACK LowLevelMouseFilterProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	// Are we expected to handle this callback?
	if (nCode == HC_ACTION)
	{
		// Is this mouse event "real" or "injected"
		// i.e. hardware or software-produced?
		MSLLHOOKSTRUCT *hookStruct = (MSLLHOOKSTRUCT*)lParam;
		if (!(hookStruct->flags & LLMHF_INJECTED)) {

			return TRUE;
		}
	}

	// Otherwise, pass on the message
	return CallNextHookEx(hLLMouseHook, nCode, wParam, lParam);
}

LRESULT CALLBACK LowLevelMousePriorityProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	// Are we expected to handle this callback?
	// do we have a target window handle?
	if (nCode == HC_ACTION && hMousePriorityWindow != NULL)
	{
		// Is this mouse event "real" or "injected"
		// i.e. hardware or software-produced?
		MSLLHOOKSTRUCT *hookStruct = (MSLLHOOKSTRUCT*)lParam;
		if (!(hookStruct->flags & LLMHF_INJECTED)) {
			// Message was not injected - send RFB_LOCAL_MOUSE msg!
			// Remote event will be blocked
			PostMessage(
				hMousePriorityWindow,
				LocalMouseMessage,
				0,
				0
				);
		}
	}

	// Otherwise, pass on the message
	return CallNextHookEx(hLLMousePrHook, nCode, wParam, lParam);
}

#endif

LRESULT CALLBACK KeyboardPriorityProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	// Are we expected to handle this callback?
	// do we have a target window handle?
	if (nCode == HC_ACTION && hKeyboardPriorityWindow != NULL)
	{
			PostMessage(
			hKeyboardPriorityWindow,
			LocalKeyboardMessage,
			0,
			0
			);
		
	}

	return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}


LRESULT CALLBACK MousePriorityProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	// Are we expected to handle this callback?
	// do we have a target window handle?
	if (nCode == HC_ACTION && hMousePriorityWindow != NULL)
	{
		if ( (wParam == WM_LBUTTONDOWN) || (wParam == WM_RBUTTONDOWN) || (wParam == WM_MBUTTONDOWN) || (wParam == WM_MOUSEMOVE) )
			PostMessage(
			hMousePriorityWindow,
			LocalMouseMessage,
			0,
			0
			);
	}

	return CallNextHookEx(hMouseHook, nCode, wParam, lParam);
}


char * NameFromPath(const char *path)
{
	int x;
	int l = strlen(path);
	char *temp = NULL;
	
	// Find the file part of a filename
	for (x=l-1; x>0; x--)
	{
		if (path[x] == '\\')
		{
			temp = strdup(&(path[x+1]));
			break;
		}
	}

	// If we didn't fine a \ then just return a copy of the original
	if (temp == NULL)
		temp = strdup(path);

	return temp;
}

/////////////////////////////////////////////////////////////////////////////
// Initialise / Exit routines.
// These functions handle the update settings for any apps used with WinVNC.

static const TCHAR szSoftware[] = "Software";
static const TCHAR szCompany[] = "ORL";
static const TCHAR szProfile[] = "VNCHooks";

HKEY GetRegistryKey()
{
	HKEY hAppKey = NULL;
	HKEY hSoftKey = NULL;
	HKEY hCompanyKey = NULL;
	if (RegOpenKeyEx(HKEY_CURRENT_USER, szSoftware, 0, KEY_WRITE|KEY_READ,
		&hSoftKey) == ERROR_SUCCESS)
	{
		DWORD dw;
		if (RegCreateKeyEx(hSoftKey, szCompany, 0, REG_NONE,
			REG_OPTION_NON_VOLATILE, KEY_WRITE|KEY_READ, NULL,
			&hCompanyKey, &dw) == ERROR_SUCCESS)
		{
			RegCreateKeyEx(hCompanyKey, szProfile, 0, REG_NONE,
				REG_OPTION_NON_VOLATILE, KEY_WRITE|KEY_READ, NULL,
				&hAppKey, &dw);
		}
	}
	if (hSoftKey != NULL)
		RegCloseKey(hSoftKey);
	if (hCompanyKey != NULL)
		RegCloseKey(hCompanyKey);

	return hAppKey;
}

HKEY GetModuleKey(const char *proc_name)
{
	HKEY hModule = NULL;

	// Work out the registry key to save this under
	sModulePrefs = (char *) malloc(strlen(sPrefSegment) + strlen(proc_name) + 1);
	if (sModulePrefs == NULL)
		return FALSE;
	sprintf(sModulePrefs, "%s%s", sPrefSegment, proc_name);

	// Check whether the library's entry exists!
	HKEY hAppKey = GetRegistryKey();
	if (hAppKey == NULL)
		return NULL;

	// Attempt to open the section for this application
	if (RegOpenKeyEx(hAppKey,
					sModulePrefs,
					0, KEY_WRITE|KEY_READ,
					&hModule
					) != ERROR_SUCCESS)
	{
		// Cut off the app directory and just use the name
		char *file_name = NameFromPath(proc_name);

		if (file_name == NULL)
		{
			RegCloseKey(hAppKey);
			return NULL;
		}

		// Adjust the moduleprefs name
		sprintf(sModulePrefs, "%s%s", sPrefSegment, file_name);
		free(file_name);

		// Now get the module key again
		DWORD dw;
		if (RegCreateKeyEx(hAppKey,
					sModulePrefs,
					0, REG_NONE, REG_OPTION_NON_VOLATILE,
					KEY_WRITE|KEY_READ,
					NULL,
					&hModule,
					&dw) != ERROR_SUCCESS)
		{
			// Couldn't find/create the key - fail!
			RegCloseKey(hAppKey);
			return NULL;
		}
	}

	// Close the application registry key
	RegCloseKey(hAppKey);

	return hModule;
}

int GetProfileInt(LPTSTR key, int def)
{
	DWORD type;
	DWORD value;
	ULONG size = sizeof(value);

	if (RegQueryValueEx(
		hModuleKey,
		key,
		NULL,
		&type,
		(unsigned char *)&value,
		&size) == ERROR_SUCCESS)
	{
		// Is the value of the right type?
		if (type != REG_DWORD)
		{
			return def;
		}
		else
		{
			return value;
		}
	}
	else
	{
		return def;
	}
}

void WriteProfileInt(LPTSTR key, int value)
{
	RegSetValueEx(
		hModuleKey,
		key,
		0,
		REG_DWORD,
		(unsigned char *)&value,
		sizeof(value));
}

BOOL InitInstance() 
{
	// Create the global atoms
	VNC_WINDOWPOS_ATOM = GlobalAddAtom(VNC_WINDOWPOS_ATOMNAME);
	if (VNC_WINDOWPOS_ATOM == NULL)
		return FALSE;
	VNC_POPUPSELN_ATOM = GlobalAddAtom(VNC_POPUPSELN_ATOMNAME);
	if (VNC_POPUPSELN_ATOM == NULL)
		return FALSE;

	// Get the module name
	char proc_name[_MAX_PATH];
	DWORD size;

	// Attempt to get the program/module name
	if ((size = GetModuleFileName(
		GetModuleHandle(NULL),
		(char *) &proc_name,
		_MAX_PATH
		)) == 0)
		return FALSE;

	// Get the key for the module
	hModuleKey = GetModuleKey(proc_name);
	if (hModuleKey == NULL)
		return FALSE;

	// Read in the prefs
	prf_use_GetUpdateRect = GetProfileInt(
		"use_GetUpdateRect",
		TRUE
		);

	prf_use_Timer = GetProfileInt(
		"use_Timer",
		FALSE
		);
	prf_use_KeyPress = GetProfileInt(
		"use_KeyPress",
		TRUE
		);
	prf_use_LButtonUp = GetProfileInt(
		"use_LButtonUp",
		TRUE
		);
	prf_use_MButtonUp = GetProfileInt(
		"use_MButtonUp",
		TRUE
		);
	prf_use_RButtonUp = GetProfileInt(
		"use_RButtonUp",
		TRUE
		);
	prf_use_Deferral = GetProfileInt(
		"use_Deferral",
#ifdef HORIZONLIVE
		FALSE	// we use full screen polling anyway
#else
		TRUE
#endif
		);

	return TRUE;
}

BOOL ExitInstance() 
{
	// Free the created atoms
	if (VNC_WINDOWPOS_ATOM != NULL)
	{
		GlobalDeleteAtom(VNC_WINDOWPOS_ATOM);
		VNC_WINDOWPOS_ATOM = NULL;
	}
	if (VNC_POPUPSELN_ATOM != NULL)
	{
		GlobalDeleteAtom(VNC_POPUPSELN_ATOM);
		VNC_POPUPSELN_ATOM = NULL;
	}

	// Write the module settings to disk
	if (sModulePrefs != NULL)
	{
		WriteProfileInt(
			"use_GetUpdateRect",
			prf_use_GetUpdateRect
			);

		WriteProfileInt(
			"use_Timer",
			prf_use_Timer
			);

		WriteProfileInt(
			"use_KeyPress",
			prf_use_KeyPress
			);

		WriteProfileInt(
			"use_LButtonUp",
			prf_use_LButtonUp
			);

		WriteProfileInt(
			"use_MButtonUp",
			prf_use_MButtonUp
			);

		WriteProfileInt(
			"use_RButtonUp",
			prf_use_RButtonUp
			);

		WriteProfileInt(
			"use_Deferral",
			prf_use_Deferral
			);

		free(sModulePrefs);
		sModulePrefs = NULL;
	}

	// Close the registry key for this module
	if (hModuleKey != NULL)
		RegCloseKey(hModuleKey);

	return TRUE;
}
