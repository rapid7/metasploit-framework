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


// vncInstHandler

// The WinMain procedure for WinVNC produces one of these objects.
// It creates a named mutex and checks to see whether that mutex
// already existed in the system.  If it did, then there is a previous
// instance of WinVNC running, which must be requested to quit cleanly.

class vncInstHandler;

#if (!defined(_WINVNC_VNCINSTHANDLER))
#define _WINVNC_VNCINSTHANDLER

// Includes
#include "stdhdrs.h"

// The vncInstHandler class itself
class vncInstHandler
{
public:
	vncInstHandler();
	~vncInstHandler();

	// check to see if an instance is already running
	BOOL Init();
	DWORD Release();

private:
	HANDLE m_mutex;
};

#endif // _WINVNC_VNCINSTHANDLER
