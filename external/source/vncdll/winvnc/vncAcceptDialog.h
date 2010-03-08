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

class vncAcceptDialog;

#if (!defined(_WINVNC_VNCACCEPTDIALOG))
#define _WINVNC_VNCACCEPTDIALOG

#pragma once

// Incoming connection-rejection dialog.  vncClient creates an AcceptDialog
// if it needs to query whether or not to accept a connection.

class vncAcceptDialog  
{
public:

	// Create an outgoing-connection dialog
	vncAcceptDialog(UINT timeoutSecs,
					BOOL acceptOnTimeout,
					BOOL allowNoPass,
					const char *ipAddress);

	// Destructor
	virtual ~vncAcceptDialog();

	// Once a dialog object is created, either delete it again, or
	// call DoDialog.  DoDialog will run the dialog and return
	// TRUE (Accept) or FALSE (Reject).
	// 1: Accept, 2: Accept w/o Password
	// The function will also return false (or true, if set to accept at timeout)
	// if the dialog times out.
	BOOL DoDialog();

	// Internal stuffs
private:

	// Routine to call when a dialog event occurs
	static BOOL CALLBACK vncAcceptDlgProc(HWND hwndDlg,
										UINT uMsg, 
										WPARAM wParam,
										LPARAM lParam);

	// Storage for the timeout value
	UINT m_timeoutSecs;
	UINT m_timeoutCount;

	// Flashing hack
	BOOL m_foreground_hack;
	BOOL m_flash_state;

	// Address of the offending machine
	char *m_ipAddress;

	// Whether to accept or reject on default/timeout
	BOOL m_acceptOnTimeout;
	BOOL m_allowNoPass;

};

#endif
