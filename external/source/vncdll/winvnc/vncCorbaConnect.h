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


// vncCorbaConnect

// The vncCorbaConnect object makes the WinVNC server available through
// the CORBA desktop control interface

class vncCorbaConnect;

#if (!defined(_WINVNC_VNCCORBACONNECT))
#define _WINVNC_VNCCORBACONNECT

// Includes
#include "stdhdrs.h"

// The following class definition is only used if CORBA control
// is to be enabled in the final executable
#if(defined(_CORBA))

#include <omniorb2/CORBA.h>
#include <omnithread.h>
#include "vnc.hh"
#include "vncServer.h"

// The vncCorbaConnect class itself
class vncCorbaConnect
{
public:
	// Constructor/destructor
	vncCorbaConnect();
	~vncCorbaConnect();

	// Init
	virtual BOOL Init(vncServer *server);

	// Implementation
protected:
	// Internal methods
	virtual BOOL InitQuiet(vncServer *server);
	virtual BOOL InitCorba(int argc, char *argv[]);
	virtual void ShutdownCorba(void);
	virtual CORBA::Boolean BindDesktop(CORBA::Object_ptr obj);

	// General
	vncServer			*m_server;

	// The actual CORBA stuff;
	CORBA::ORB_ptr		m_orb;						// The overall ORB object
	CORBA::BOA_ptr		m_boa;

	vnc::_sk_controller	*m_controller;

	char				*m_username;
	char				*m_desktop;

	CORBA::ULong		m_lastconntime;

	omni_mutex			m_updateLock;
	
	UINT				m_port;
};

#else // _CORBA

#include "vncServer.h"

// The vncCorbaConnect class itself

class vncCorbaConnect
{
public:
	// Init
	virtual BOOL Init(vncServer *server) {return FALSE;};
};

#endif // _CORBA

#endif // _WINVNC_VNCCORBACONNECT
