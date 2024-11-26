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

class vncConnDialog;

#if (!defined(_WINVNC_VNCCONNDIALOG))
#define _WINVNC_VNCCONNDIALOG

#pragma once

#include "vncServer.h"

// Outgoing connection dialog.  This allows people running VNC servers on
// Win32 platforms to _push_ their displays out to other people's screens
// rather than having to _pull_ them across.

class vncConnDialog  
{
public:

	// Create an outgoing-connection dialog
	vncConnDialog(vncServer *server);

	// Destructor
	virtual ~vncConnDialog();

	// Once a dialog object is created, either delete it again, or
	// call DoDialog.  DoDialog will run the object and delete it when done
	void DoDialog();

	// Internal stuffs
private:

	// Routine to call when a dialog event occurs
	static BOOL CALLBACK vncConnDlgProc(HWND hwndDlg,
										UINT uMsg, 
										WPARAM wParam,
										LPARAM lParam);

	// Pointer back to the server object
	vncServer *m_server;
};

#endif
