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


// vncSockConnect.cpp

// Implementation of the listening socket class

#include "stdhdrs.h"
#include "VSocket.h"
#include "vncSockConnect.h"
#include "vncServer.h"
#include <omnithread.h>

// The function for the spawned thread to run
class vncSockConnectThread : public omni_thread
{
public:
	// Init routine
	virtual BOOL Init(VSocket *socket, vncServer *server);

	// Code to be executed by the thread
	virtual void *run_undetached(void * arg);

	// Fields used internally
	BOOL		m_shutdown;
protected:
	VSocket		*m_socket;
	vncServer	*m_server;
};

// Method implementations
BOOL vncSockConnectThread::Init(VSocket *socket, vncServer *server)
{
	// Save the server pointer
	m_server = server;

	// Save the socket pointer
	m_socket = socket;

	// Start the thread
	m_shutdown = FALSE;
	start_undetached();

	return TRUE;
}

// Code to be executed by the thread
void *vncSockConnectThread::run_undetached(void * arg)
{
	// Go into a loop, listening for connections on the given socket
	/*while (!m_shutdown) {
		// Accept an incoming connection
		VSocket *new_socket;
		if (!m_socket->TryAccept(&new_socket, 100))
			break;
		if (new_socket != NULL) {

			// Successful accept - start the client unauthenticated
			m_server->AddClient(new_socket, FALSE, FALSE);
		}
	}*/

	return NULL;
}

// The vncSockConnect class implementation

vncSockConnect::vncSockConnect()
{
	m_thread = NULL;
}

vncSockConnect::~vncSockConnect()
{
    m_socket.Shutdown();

    // Join with our lovely thread
    if (m_thread != NULL) {
		((vncSockConnectThread *)m_thread)->m_shutdown = TRUE;

		void *returnval;
		m_thread->join(&returnval);
		m_thread = NULL;

		m_socket.Close();
    }
}

BOOL vncSockConnect::Init(vncServer *server, UINT port)
{
	// Save the port id
	m_port = port;

	// Create the listening socket
	if (!m_socket.Create())
		return FALSE;

	// Bind it
	if (!m_socket.Bind(m_port, server->LoopbackOnly()))
		return FALSE;

	// Set it to listen
	if (!m_socket.Listen())
		return FALSE;

	// Create the new thread
	m_thread = new vncSockConnectThread;
	if (m_thread == NULL)
		return FALSE;

	// And start it running
	return ((vncSockConnectThread *)m_thread)->Init(&m_socket, server);
}

