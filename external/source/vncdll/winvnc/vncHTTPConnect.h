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


// vncHTTPConnect.h

// The vncHTTPConnect class creates a listening socket and binds
// it to the specified port number.  It then creates a listen
// thread which goes into a loop, listening on the socket.
// When the vncHTTPConnect object is destroyed, all resources are
// freed automatically, including the listen thread.
// This server allows clients to request the java classes required
// to view the desktop remotely.

class vncHTTPConnect;

#if (!defined(_WINVNC_VNCHTTPCONNECT))
#define _WINVNC_VNCHTTPCONNECT

// Includes
#include "stdhdrs.h"
#include "VSocket.h"
#include "vncServer.h"
#include <omnithread.h>

// The vncHTTPConnect class itself
class vncHTTPConnect
{
public:
	// Constructor/destructor
	vncHTTPConnect();
	~vncHTTPConnect();

	// Init
	virtual VBool Init(vncServer *server, UINT listen_port, BOOL allow_params);

	// Implementation
protected:
	// The listening socket
	VSocket m_listen_socket;

	// The port to listen on
	UINT m_listen_port;

	// The in-coming accept thread
	omni_thread *m_listen_thread;

	// Allow passing applet parameters in the URL
	BOOL m_allow_params;
};

#endif // _WINVNC_VNCHTTPCONNECT
