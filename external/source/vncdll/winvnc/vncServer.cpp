//  Copyright (C) 2000 Tridia Corporation. All Rights Reserved.
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


// vncServer.cpp

// vncServer class implementation

// Includes
#include "stdhdrs.h"
#include <omnithread.h>
#include <string.h>
#include <lmcons.h>

// Custom
#include "vncServer.h"
#include "vncSockConnect.h"
#include "vncCorbaConnect.h"
#include "vncClient.h"
#include "vncService.h"

// Constructor/destructor
vncServer::vncServer()
{
	ResetPasswordsValidityInfo();

	// Initialise some important stuffs...
	m_socketConn = NULL;
	m_corbaConn = NULL;
	//m_httpConn = NULL;
	m_desktop = NULL;
	m_name = NULL;
	SetName("");
	m_port = DISPLAY_TO_PORT(0);
	m_port_http = DISPLAY_TO_HPORT(0);
	m_autoportselect = TRUE;
	m_passwd_required = FALSE;
	m_beepConnect = FALSE;
	m_beepDisconnect = FALSE;
	m_auth_hosts = 0;
	m_blacklist = 0;
	//{
	//	vncPasswd::FromClear clearPWD;
		memcpy(m_password, "", MAXPWLEN);
		m_password_set = FALSE;
		memcpy(m_password_viewonly, "", MAXPWLEN);
		m_password_viewonly_set = FALSE;
	//}
	m_querysetting = 2;
	m_querytimeout = 10;
	m_queryaccept = FALSE;
	m_queryallownopass = FALSE;

	// Autolock settings
	m_lock_on_exit = 0;

	// Set the polling mode options
	m_poll_fullscreen = TRUE;
	m_poll_foreground = TRUE;
	m_poll_undercursor = TRUE;

	m_poll_oneventonly = FALSE;
	m_poll_consoleonly = FALSE;

	m_dont_set_hooks = FALSE;
	m_dont_use_driver = FALSE;
	m_driver_direct_access_en = TRUE;

	// General options
	m_loopbackOnly = TRUE;
	m_disableTrayIcon = TRUE;
	m_loopback_allowed = TRUE;
	m_httpd_enabled = FALSE;
	m_httpd_params_enabled = FALSE;
	m_lock_on_exit = 0;
	m_connect_pri = 0;

	// Set the input options
	m_enable_remote_inputs = TRUE;
	m_disable_local_inputs = FALSE;

	// Clear the client mapping table
	for (int x=0; x<MAX_CLIENTS; x++)
		m_clientmap[x] = NULL;
	m_nextid = 0;

	// Signal set when a client quits
	m_clientquitsig = new omni_condition(&m_clientsLock);
	m_clients_disabled = FALSE;
	m_local_input_priority = FALSE;

	m_full_screen = TRUE;
	m_WindowShared= FALSE;
	m_hwndShared = NULL;
	m_screen_area = FALSE;
	m_primary_display_only_shared = FALSE;
	m_disable_time = 3;
	SetSharedRect(GetScreenRect());
	SetPollingCycle(300);
	PollingCycleChanged(false);
	m_cursor_pos.x = 0;
	m_cursor_pos.y = 0;

	// initialize
	m_enable_file_transfers = FALSE;
	m_remove_wallpaper = FALSE;
	m_blank_screen = FALSE;

#ifdef HORIZONLIVE
	m_full_screen = FALSE;
	m_WindowShared= TRUE;
	m_local_input_priority = TRUE;
	m_remote_mouse = 1;
	m_remote_keyboard = 1;
#endif

	m_wallpaper_wait = FALSE;
}

vncServer::~vncServer()
{
	// If there is a socket_conn object then delete it
	if (m_socketConn != NULL)
	{
		delete m_socketConn;
		m_socketConn = NULL;
	}

	if (m_corbaConn != NULL)
	{
		delete m_corbaConn;
		m_corbaConn = NULL;
	}

	/*if (m_httpConn != NULL)
	{
		delete m_httpConn;
		m_httpConn = NULL;
	}*/

	// Remove any active clients!
	KillAuthClients();
	KillUnauthClients();

	// Wait for all the clients to die
	WaitUntilAuthEmpty();
	WaitUntilUnauthEmpty();

	// Don't free the desktop until no KillClient is likely to free it
	{	omni_mutex_lock l(m_desktopLock);

		if (m_desktop != NULL)
		{
			delete m_desktop;
			m_desktop = NULL;
		}
	}

	// Don't free the authhosts string until no more connections are possible
	if (m_auth_hosts != 0)
	{
		free(m_auth_hosts);
		m_auth_hosts = 0;
	}

	if (m_name != NULL)
	{
		free(m_name);
		m_name = NULL;
	}

	if (m_clientquitsig != NULL)
	{
		delete m_clientquitsig;
		m_clientquitsig = NULL;
	}
}

// Client handling functions
void
vncServer::DisableClients(BOOL state)
{
	m_clients_disabled = state;
}

BOOL
vncServer::ClientsDisabled()
{
	return m_clients_disabled;
}

vncClientId vncServer::AddClient( AGENT_CTX * lpAgentContext )
{
	vncClient *client = NULL;
	VSocket * socket = NULL;

	omni_mutex_lock l(m_clientsLock);

	socket = new VSocket( &lpAgentContext->info, lpAgentContext->hCloseEvent );

	// Try to allocate a client id...
	vncClientId clientid = m_nextid;
	do
	{
		clientid = (clientid+1) % MAX_CLIENTS;
		if (clientid == m_nextid)
		{
			delete socket;
			return -1;
		}
	}
	while (m_clientmap[clientid] != NULL);

	// Create a new client and add it to the relevant client list
	client = new vncClient();
	if (client == NULL) {
		delete socket;
		return -1;
	}

	// Set the client's settings
	client->EnableKeyboard(TRUE && m_enable_remote_inputs);
	client->EnablePointer(TRUE && m_enable_remote_inputs);

	// Start the client
	if (!client->Init(this, socket, TRUE, TRUE, clientid, lpAgentContext ))
	{
		// The client will delete the socket for us...
		delete client;
		return -1;
	}

	m_clientmap[clientid] = client;

	// Add the client to unauth the client list
	m_unauthClients.push_back(clientid);

	// Notify anyone interested about this event
	//DoNotify(WM_SRV_CLIENT_CONNECT, 0, 0);

	return clientid;
}

BOOL
vncServer::Authenticated(vncClientId clientid)
{
	vncClientList::iterator i;
	BOOL authok = TRUE;

	omni_mutex_lock l1(m_desktopLock);
	omni_mutex_lock l2(m_clientsLock);

	// Search the unauthenticated client list
	for (i = m_unauthClients.begin(); i != m_unauthClients.end(); i++)
	{
		// Is this the right client?
		if ((*i) == clientid)
		{
			vncClient *client = GetClient(clientid);

			// Yes, so remove the client and add it to the auth list
			m_unauthClients.erase(i);

			// Create the screen handler if necessary
			if (m_desktop == NULL)
			{
				if (RemoveWallpaperEnabled()) {
					m_wallpaper_wait = TRUE;
					//DoNotify(WM_SRV_CLIENT_HIDEWALLPAPER, 0, 0);
				}
				m_desktop = new vncDesktop();
				if (m_desktop == NULL)
				{
					client->Kill();
					authok = FALSE;
					break;
				}
				if (!m_desktop->Init(this))
				{

					client->Kill();
					authok = FALSE;

					delete m_desktop;
					m_desktop = NULL;

					break;
				}
			}

			// Create a buffer object for this client
			vncBuffer *buffer = new vncBuffer(m_desktop);
			if (buffer == NULL)
			{
				client->Kill();
				authok = FALSE;
				break;
			}

			// Tell the client about this new buffer
			client->SetBuffer(buffer);

			// Add the client to the auth list
			m_authClients.push_back(clientid);

			break;
		}
	}

	// Notify anyone interested of this event
	//DoNotify(WM_SRV_CLIENT_AUTHENTICATED, 0, 0);

	// If so configured, beep to indicate the new connection is
	// present.
	if (authok && GetBeepConnect())
	{
		MessageBeep(MB_OK);
	}

	return authok;
}

void
vncServer::KillClient(vncClientId clientid)
{
	vncClientList::iterator i;
	BOOL done = FALSE;

	omni_mutex_lock l(m_clientsLock);

	// Find the client in one of the two lists
	for (i = m_unauthClients.begin(); i != m_unauthClients.end(); i++)
	{
		// Is this the right client?
		if ((*i) == clientid)
		{
			// Ask the client to die
			vncClient *client = GetClient(clientid);
			client->Kill();

			done = TRUE;
			break;
		}
	}
	if (!done)
	{
		for (i = m_authClients.begin(); i != m_authClients.end(); i++)
		{
			// Is this the right client?
			if ((*i) == clientid)
			{
				// Yes, so kill it
				vncClient *client = GetClient(clientid);
				client->Kill();

				done = TRUE;
				break;
			}
		}
	}

}

void
vncServer::KillAuthClients()
{
	vncClientList::iterator i;
	omni_mutex_lock l(m_clientsLock);

	// Tell all the authorised clients to die!
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		// Kill the client
		GetClient(*i)->Kill();
	}
}

void
vncServer::KillUnauthClients()
{
	vncClientList::iterator i;
	omni_mutex_lock l(m_clientsLock);

	// Tell all the authorised clients to die!
	for (i = m_unauthClients.begin(); i != m_unauthClients.end(); i++)
	{
		// Kill the client
		GetClient(*i)->Kill();
	}
}

size_t
vncServer::AuthClientCount()
{
	omni_mutex_lock l(m_clientsLock);

	return m_authClients.size();
}

size_t
vncServer::UnauthClientCount()
{
	omni_mutex_lock l(m_clientsLock);

	return m_unauthClients.size();
}

void
vncServer::WaitUntilAuthEmpty()
{
	omni_mutex_lock l(m_clientsLock);

	// Wait for all the clients to exit
	while (!m_authClients.empty())
	{
		// Wait for a client to quit
		m_clientquitsig->wait();
	}
}

void
vncServer::WaitUntilUnauthEmpty()
{
	omni_mutex_lock l(m_clientsLock);

	// Wait for all the clients to exit
	while (!m_unauthClients.empty())
	{
		// Wait for a client to quit
		m_clientquitsig->wait();
	}
}

BOOL
vncServer::RemoteEventReceived()
{
	vncClientList::iterator i;
	BOOL result = FALSE;
	omni_mutex_lock l(m_clientsLock);

	// Iterate over the authorised clients
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		result = result || GetClient(*i)->RemoteEventReceived();
	}
	return result;
}

// Client info retrieval/setup
vncClient*
vncServer::GetClient(vncClientId clientid)
{
	if ((clientid >= 0) && (clientid < MAX_CLIENTS))
		return m_clientmap[clientid];
	return NULL;
}

vncClientList
vncServer::ClientList()
{
	vncClientList clients;

	omni_mutex_lock l(m_clientsLock);

	clients = m_authClients;

	return clients;
}

void
vncServer::BlockRemoteInput(BOOL block)
{
	omni_mutex_lock l(m_clientsLock);

	vncClientList::iterator i;
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
		GetClient(*i)->BlockInput(block);
}

const char*
vncServer::GetClientName(vncClientId clientid)
{
	omni_mutex_lock l(m_clientsLock);

	vncClient *client = GetClient(clientid);
	if (client != NULL)
		return client->GetClientName();
	return NULL;
}

// RemoveClient should ONLY EVER be used by the client to remove itself.
void
vncServer::RemoveClient(vncClientId clientid)
{
	vncClientList::iterator i;
	BOOL done = FALSE;

	omni_mutex_lock l1(m_desktopLock);
	{	omni_mutex_lock l2(m_clientsLock);

		// Find the client in one of the two lists
		for (i = m_unauthClients.begin(); i != m_unauthClients.end(); i++)
		{
			// Is this the right client?
			if ((*i) == clientid)
			{
				// Yes, so remove the client and kill it
				m_unauthClients.erase(i);
				m_clientmap[clientid] = NULL;

				done = TRUE;
				break;
			}
		}
		if (!done)
		{
			for (i = m_authClients.begin(); i != m_authClients.end(); i++)
			{
				// Is this the right client?
				if ((*i) == clientid)
				{
					// Yes, so remove the client and kill it
					m_authClients.erase(i);
					m_clientmap[clientid] = NULL;

					done = TRUE;
					break;
				}
			}
		}

		// Signal that a client has quit
		m_clientquitsig->signal();

	} // Unlock the clientLock

	// If so configured, beep to indicate the old connection is
	// gone.
	if (GetBeepDisconnect())
	{
		MessageBeep(MB_OK);
	}

	// Are there any authorised clients connected?
	if (m_authClients.empty() && (m_desktop != NULL))
	{
		// Are there locksettings set?
		if (LockSettings() == 1)
		{
			// Yes - lock the machine on disconnect!
			vncService::LockWorkstation();
		} else if (LockSettings() > 1)
		{
		    char username[UNLEN+1];

		    vncService::CurrentUser((char *)&username, sizeof(username));
		    if (strcmp(username, "") != 0)
		    {
			// Yes - force a user logoff on disconnect!
				ExitWindowsEx(EWX_LOGOFF, 0);
		    }
		}

		// Delete the screen server
		delete m_desktop;
		m_desktop = NULL;
	}

	// Notify anyone interested of the change
	//DoNotify(WM_SRV_CLIENT_DISCONNECT, 0, 0);
}

// NOTIFICATION HANDLING!

// Connect/disconnect notification
BOOL
vncServer::AddNotify(HWND hwnd)
{
	omni_mutex_lock l(m_clientsLock);

	// Add the window handle to the list
	m_notifyList.push_front(hwnd);

	return TRUE;
}

BOOL
vncServer::RemNotify(HWND hwnd)
{
	omni_mutex_lock l(m_clientsLock);

	// Remove the window handle from the list
	vncNotifyList::iterator i;
	for (i=m_notifyList.begin(); i!=m_notifyList.end(); i++)
	{
		if ((*i) == hwnd)
		{
			// Found the handle, so remove it
			m_notifyList.erase(i);
			return TRUE;
		}
	}

	return FALSE;
}

// Send a notification message
void
vncServer::DoNotify(UINT message, WPARAM wparam, LPARAM lparam)
{
	omni_mutex_lock l(m_clientsLock);

	// Send the given message to all the notification windows
	vncNotifyList::iterator i;
	for (i=m_notifyList.begin(); i!=m_notifyList.end(); i++)
	{
		PostMessage((*i), message, wparam, lparam);
	}
}

// Client->Desktop update signalling
void
vncServer::RequestUpdate()
{
	omni_mutex_lock l(m_desktopLock);
	if (m_desktop != NULL)
	{
		m_desktop->RequestUpdate();
	}
}

// Update handling
void
vncServer::TriggerUpdate()
{
	vncClientList::iterator i;
	
	omni_mutex_lock l(m_clientsLock);

	// Post this update to all the connected clients
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		// Post the update
		GetClient(*i)->TriggerUpdate();
	}
}

void
vncServer::UpdateRect(RECT &rect)
{
	vncClientList::iterator i;
	
	omni_mutex_lock l(m_clientsLock);

	// Post this update to all the connected clients
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		// Post the update
		GetClient(*i)->UpdateRect(rect);
	}
}



void
vncServer::UpdateRegion(vncRegion &region)
{
	vncClientList::iterator i;
	
	omni_mutex_lock l(m_clientsLock);

		
	// Post this update to all the connected clients
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		// Post the update
			GetClient(*i)->UpdateRegion(region);
	}
}

void
vncServer::CopyRect(RECT &dest, POINT &source)
{
	vncClientList::iterator i;
	
	omni_mutex_lock l(m_clientsLock);

	// Post this update to all the connected clients
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		// Post the update
		GetClient(*i)->CopyRect(dest, source);
	}
}

void
vncServer::UpdateMouse()
{
	vncClientList::iterator i;
	
	omni_mutex_lock l(m_clientsLock);

	// Post this mouse update to all the connected clients
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		// Post the update
		GetClient(*i)->UpdateMouse();
	}
}

void
vncServer::UpdateClipText(LPSTR text)
{
	vncClientList::iterator i;
	
	omni_mutex_lock l(m_clientsLock);

	// Post this update to all the connected clients
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		// Post the update
		GetClient(*i)->UpdateClipText(text);
	}
}

void
vncServer::UpdatePalette()
{
	vncClientList::iterator i;
	
	omni_mutex_lock l(m_clientsLock);

	// Post this update to all the connected clients
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		// Post the update
		GetClient(*i)->UpdatePalette();
	}
}

void
vncServer::UpdateLocalClipText(LPSTR text)
{
	omni_mutex_lock l(m_desktopLock);

	if (m_desktop != NULL)
		m_desktop->SetClipText(text);
}

// Changing hook settings

void
vncServer::DontSetHooks(BOOL enable)
{
	m_dont_set_hooks = enable;
	if (m_desktop != NULL)
		m_desktop->TryActivateHooks();
}

// Changing use driver settings

void
vncServer::DontUseDriver(BOOL enable)
{
	m_dont_use_driver = enable;
}

void
vncServer::DriverDirectAccess(BOOL enable)
{
	m_driver_direct_access_en = enable;
}

// Name and port number handling
void
vncServer::SetName(const char * name)
{
	// Set the name of the desktop
	if (m_name != NULL)
	{
		free(m_name);
		m_name = NULL;
	}
	
	m_name = strdup(name);
}

void
vncServer::SetPorts(const UINT port_rfb, const UINT port_http)
{
	if (m_port != port_rfb || m_port_http != port_http) {
		// Set port numbers to use
		m_port = port_rfb;
		m_port_http = port_http;

		// If there is already a listening socket then close and re-open it...
		BOOL socketon = SockConnected();
		SockConnect(FALSE);
		if (socketon)
			SockConnect(TRUE);
    }
}

void
vncServer::SetPassword(BOOL activate, const char *passwd)
{
	ResetPasswordsValidityInfo();
	m_password_set = activate;
	memcpy(m_password, passwd, MAXPWLEN);
}

BOOL
vncServer::GetPassword(char *passwd)
{
	memcpy(passwd, m_password, MAXPWLEN);
	return m_password_set;
}

void
vncServer::SetPasswordViewOnly(BOOL activate, const char *passwd)
{
	ResetPasswordsValidityInfo();
	m_password_viewonly_set = activate;
	memcpy(m_password_viewonly, passwd, MAXPWLEN);
}

BOOL
vncServer::GetPasswordViewOnly(char *passwd)
{
	memcpy(passwd, m_password_viewonly, MAXPWLEN);
	return m_password_viewonly_set;
}

BOOL
vncServer::ValidPasswordsSet()
{
	if (!m_valid_passwords_set_cached) {
		m_valid_passwords_set = ValidPasswordsSet_nocache();
		m_valid_passwords_set_cached = TRUE;
	}
	return m_valid_passwords_set;
}

BOOL
vncServer::ValidPasswordsSet_nocache()
{
	char passwd1[MAXPWLEN];
	char passwd2[MAXPWLEN];
	BOOL set1 = GetPassword(passwd1);
	BOOL set2 = GetPasswordViewOnly(passwd2);
	if (!set1 && !set2)
		return FALSE;	// no passwords set, connections impossible

	if (!AuthRequired())
		return TRUE;	// passwords may be empty, but we allow that

	vncPasswd::ToText plain1(passwd1);
	vncPasswd::ToText plain2(passwd2);
	BOOL empty1 = !set1 || (strlen(plain1) == 0);
	BOOL empty2 = !set2 || (strlen(plain2) == 0);
	if (empty1 && empty2)
		return FALSE;	// both passwords empty or unset, not allowed

	return TRUE;		// at least one non-empty password
}

BOOL
vncServer::ValidPasswordsEmpty()
{
	if (!m_valid_passwords_empty_cached) {
		m_valid_passwords_empty = ValidPasswordsEmpty_nocache();
		m_valid_passwords_empty_cached = TRUE;
	}
	return m_valid_passwords_empty;
}

BOOL
vncServer::ValidPasswordsEmpty_nocache()
{
	if (AuthRequired())
		return FALSE;	// empty passwords disallowed, always fail

	char passwd1[MAXPWLEN];
	char passwd2[MAXPWLEN];
	BOOL set1 = GetPassword(passwd1);
	BOOL set2 = GetPasswordViewOnly(passwd2);
	if (!set1 && !set2)
		return FALSE;	// no passwords set, connections impossible

	vncPasswd::ToText plain1(passwd1);
	vncPasswd::ToText plain2(passwd2);
	BOOL empty1 = !set1 || (strlen(plain1) == 0);
	BOOL empty2 = !set2 || (strlen(plain2) == 0);
	if (empty1 && empty2)
		return TRUE;	// there are no passwords that are non-empty

	return FALSE;		// at least one non-empty password
}

// Remote input handling
void
vncServer::EnableRemoteInputs(BOOL enable)
{
	m_enable_remote_inputs = enable;
}

BOOL vncServer::RemoteInputsEnabled()
{
	return m_enable_remote_inputs;
}

// Local input handling
void
vncServer::DisableLocalInputs(BOOL disable)
{
	if ( m_disable_local_inputs != disable )
	{
		m_disable_local_inputs = disable;
		if ( AuthClientCount() != 0 )
			m_desktop->SetLocalInputDisableHook(disable);
	}
}

BOOL vncServer::LocalInputsDisabled()
{
	return m_disable_local_inputs;
}

void vncServer::LocalInputPriority(BOOL disable)
{
	if( m_local_input_priority != disable )
	{
		m_local_input_priority = disable;
		m_remote_mouse = 0;
		m_remote_keyboard = 0;
		if ( AuthClientCount() != 0 )
			m_desktop->SetLocalInputPriorityHook(disable);
	}
	
}  



// Socket connection handling
BOOL
vncServer::SockConnect(BOOL On)
{
	// Are we being asked to switch socket connects on or off?
	if (On)
	{
		// Is there a listening socket?
		if (m_socketConn == NULL)
		{
			m_socketConn = new vncSockConnect();
			if (m_socketConn == NULL)
				return FALSE;

			// Are we to use automatic port selection?
			if (m_autoportselect)
			{
				BOOL ok = FALSE;

				// Yes, so cycle through the ports, looking for a free one!
				for (int i = 0; i < 99; i++)
				{
					m_port = DISPLAY_TO_PORT(i);
					m_port_http = DISPLAY_TO_HPORT(i);

					// Attempt to connect to the port
					VSocket tempsock;
					if (tempsock.Create())
					{
						if (!tempsock.Connect("localhost", m_port))
						{
							// Couldn't connect, so this port is probably usable!
							if (m_socketConn->Init(this, m_port))
							{
								ok = TRUE;
								break;
							}
						}
					}
				}

				if (!ok)
				{
					delete m_socketConn;
					m_socketConn = NULL;
					return FALSE;
				}
			} else
			{
				// No autoportselect
				if (!m_socketConn->Init(this, m_port))
				{
					delete m_socketConn;
					m_socketConn = NULL;
					return FALSE;
				}
			}

			// Now let's start the HTTP connection stuff
            /*if (m_httpConn == NULL && m_httpd_enabled && m_port_http != m_port) {
				m_httpConn = new vncHTTPConnect;
				if (m_httpConn != NULL) {
					// Start up the HTTP server
					if (!m_httpConn->Init(this, m_port_http,
										  m_httpd_params_enabled)) {
						delete m_httpConn;
						m_httpConn = NULL;
						return FALSE;
					}
				}
			}*/
		}
	}
	else
	{
		// *** JNW - Trying to fix up a lock-up when the listening socket closes
#ifndef HORIZONLIVE
		KillAuthClients();
		KillUnauthClients();
		WaitUntilAuthEmpty();
		WaitUntilUnauthEmpty();
#endif

		// Is there a listening socket?
		if (m_socketConn != NULL)
		{
			// Close the socket
			delete m_socketConn;
			m_socketConn = NULL;
		}

		// Is there an HTTP socket active?
		/*if (m_httpConn != NULL)
		{
			// Close the socket
			delete m_httpConn;
			m_httpConn = NULL;
		}*/
	}

	return TRUE;
}

BOOL
vncServer::SockConnected()
{
	return m_socketConn != NULL;
}

BOOL
vncServer::SetHttpdEnabled(BOOL enable_httpd, BOOL enable_params)
{
	if (enable_httpd != m_httpd_enabled) {
		m_httpd_enabled = enable_httpd;
		m_httpd_params_enabled = enable_params;
		BOOL socketConn = SockConnected();
		SockConnect(FALSE);
		SockConnect(socketConn);
	} else {
		if (enable_params != m_httpd_params_enabled) {
			m_httpd_params_enabled = enable_params;
			if (SockConnected()) {
				SockConnect(FALSE);
				SockConnect(TRUE);
			}
		}
	}
	return TRUE;
}

BOOL
vncServer::SetLoopbackOnly(BOOL loopbackOnly)
{
	if (loopbackOnly != m_loopbackOnly)
	{
		m_loopbackOnly = loopbackOnly;
		BOOL socketConn = SockConnected();
		SockConnect(FALSE);
		SockConnect(socketConn);
	}
	return TRUE;
}

BOOL
vncServer::LoopbackOnly()
{
	return m_loopbackOnly;
}

BOOL
vncServer::SetDisableTrayIcon(BOOL disableTrayIcon)
{
	if (disableTrayIcon != m_disableTrayIcon)
	{
		m_disableTrayIcon = disableTrayIcon;
	}
	return TRUE;
}

BOOL
vncServer::GetDisableTrayIcon()
{
	return m_disableTrayIcon;
}

// CORBA connection handling
BOOL
vncServer::CORBAConnect(BOOL On)
{
	// Are we being asked to switch CORBA connects on or off?
	if (On)
	{
		// Is there a CORBA object?
		if (m_corbaConn == NULL)
		{
			m_corbaConn = new vncCorbaConnect();
		}
		if (m_corbaConn == NULL)
			return FALSE;
		if (!m_corbaConn->Init(this))
		{
			delete m_corbaConn;
			m_corbaConn = NULL;
			return FALSE;
		}
	}
	else
	{
		// Is there a listening socket?
		if (m_corbaConn != NULL)
		{
			// Close the socket
			delete m_corbaConn;
			m_corbaConn = NULL;
		}
	}

	return TRUE;
}

BOOL
vncServer::CORBAConnected()
{
	return m_corbaConn != NULL;
}

void
vncServer::GetScreenInfo(int &width, int &height, int &depth)
{
	rfbServerInitMsg scrinfo;

	omni_mutex_lock l(m_desktopLock);

	// Is a desktop object currently active?
	if (m_desktop == NULL)
	{
		vncDesktop desktop;

		// No, so create a dummy desktop and interrogate it
		if (!desktop.Init(this))
		{
			scrinfo.framebufferWidth = 0;
			scrinfo.framebufferHeight = 0;
			scrinfo.format.bitsPerPixel = 0;
		}
		else
		{
			desktop.FillDisplayInfo(&scrinfo);
		}
	}
	else
	{
		m_desktop->FillDisplayInfo(&scrinfo);
	}

	// Get the info from the scrinfo structure
	width = m_shared_rect.right - m_shared_rect.left;
	height = m_shared_rect.bottom - m_shared_rect.top;
	depth = scrinfo.format.bitsPerPixel;
}

void
vncServer::SetAuthHosts(const char*hostlist) {
	omni_mutex_lock l(m_clientsLock);

	if (m_auth_hosts != 0)
		free(m_auth_hosts);

	if (hostlist == 0) {
		m_auth_hosts = 0;
		return;
	}

	m_auth_hosts = strdup(hostlist);
}

char*
vncServer::AuthHosts() {
	omni_mutex_lock l(m_clientsLock);

	if (m_auth_hosts == 0)
		return strdup("");
	else
		return strdup(m_auth_hosts);
}

inline BOOL
MatchStringToTemplate(const char *addr, size_t addrlen,
				      const char *filtstr, size_t filtlen) {
	if (filtlen == 0)
		return 1;
	if (addrlen < filtlen)
		return 0;
	for (size_t x = 0; x < filtlen; x++) {
		if (addr[x] != filtstr[x])
			return 0;
	}
	if ((addrlen > filtlen) && (addr[filtlen] != '.'))
		return 0;
	return 1;
}

vncServer::AcceptQueryReject
vncServer::VerifyHost(const char *hostname) {
	if (ClientsDisabled())
		return vncServer::aqrReject;

	omni_mutex_lock l(m_clientsLock);

	// -=- Is the specified host blacklisted?
	vncServer::BlacklistEntry	*current = m_blacklist;
	vncServer::BlacklistEntry	*previous = 0;
	SYSTEMTIME					systime;
	FILETIME					ftime;
	LARGE_INTEGER				now;

	// Get the current time as a 64-bit value
	GetSystemTime(&systime);
	SystemTimeToFileTime(&systime, &ftime);
	now.LowPart=ftime.dwLowDateTime;now.HighPart=ftime.dwHighDateTime;
	now.QuadPart /= 10000000; // Convert it into seconds

	while (current) {

		// Has the blacklist entry timed out?
		if ((now.QuadPart - current->_lastRefTime.QuadPart) > 0) {

			// Yes.  Is it a "blocked" entry?
			if (current->_blocked) {
				// Yes, so unblock it & re-set the reference time
				current->_blocked = FALSE;
				current->_lastRefTime.QuadPart = now.QuadPart + 10;
			} else {
				// No, so remove it
				if (previous)
					previous->_next = current->_next;
				else
					m_blacklist = current->_next;
				vncServer::BlacklistEntry *next = current->_next;
				free(current->_machineName);
				delete current;
				current = next;
				continue;
			}

		}

		// Is this the entry we're interested in?
		if ((strcmp(current->_machineName, hostname) == 0) &&
			(current->_blocked)) {
			// Machine is blocked, so just reject it
			return vncServer::aqrReject;
		}

		previous = current;
		current = current->_next;
	}

	// Has a hostname been specified?
	if (hostname == 0) {
		return vncServer::aqrReject;
	}

	// Set the state machine into the correct mode & process the filter
	enum vh_Mode {vh_ExpectDelimiter, vh_ExpectIncludeExclude, vh_ExpectPattern};
	vh_Mode machineMode = vh_ExpectIncludeExclude;
	
	vncServer::AcceptQueryReject verifiedHost = vncServer::aqrAccept;

	vncServer::AcceptQueryReject patternType = vncServer::aqrReject;
	UINT authHostsPos = 0;
	UINT patternStart = 0;
	size_t hostNameLen = strlen(hostname);

	// Run through the auth hosts string until we hit the end
	if (m_auth_hosts) {
		while (1) {

			// Which mode are we in?
			switch (machineMode) {

				// ExpectIncludeExclude - we should see a + or -.
			case vh_ExpectIncludeExclude:
				if (m_auth_hosts[authHostsPos] == '+') {
					patternType = vncServer::aqrAccept;
					patternStart = authHostsPos+1;
					machineMode = vh_ExpectPattern;
				} else if (m_auth_hosts[authHostsPos] == '-') {	
					patternType = vncServer::aqrReject;
					patternStart = authHostsPos+1;
					machineMode = vh_ExpectPattern;
				} else if (m_auth_hosts[authHostsPos] == '?') {	
					patternType = vncServer::aqrQuery;
					patternStart = authHostsPos+1;
					machineMode = vh_ExpectPattern;
				} else if (m_auth_hosts[authHostsPos] != '\0') {
					machineMode = vh_ExpectDelimiter;
				}
				break;

				// ExpectPattern - we expect to see a valid pattern
			case vh_ExpectPattern:
				// ExpectDelimiter - we're scanning for the next ':', skipping a pattern
			case vh_ExpectDelimiter:
				if ((m_auth_hosts[authHostsPos] == ':') ||
					(m_auth_hosts[authHostsPos] == '\0')) {
					if (machineMode == vh_ExpectPattern) {
						if (patternStart == 0) {

						} else {
							// Process the match
							if (MatchStringToTemplate(hostname, hostNameLen,
								&(m_auth_hosts[patternStart]), authHostsPos-patternStart)) {
								// The hostname matched - apply the include/exclude rule
								verifiedHost = patternType;
							}
						}
					}

					// We now expect another + or -
					machineMode = vh_ExpectIncludeExclude;
				}
				break;
			}

			// Have we hit the end of the pattern string?
			if (m_auth_hosts[authHostsPos] == '\0')
				break;
			authHostsPos++;
		}
	}

	return AdjustVerification(verifiedHost);
}


vncServer::AcceptQueryReject
vncServer::AdjustVerification(vncServer::AcceptQueryReject host)
{
	vncServer::AcceptQueryReject verifiedHost = host;

	// Based on the server's QuerySetting, adjust the verification result
	switch (host) {
	case vncServer::aqrAccept:
		if (QuerySetting() >= 3)
			verifiedHost = vncServer::aqrQuery;
		break;
	case vncServer::aqrQuery:
		if (QuerySetting() <= 1)
			verifiedHost = vncServer::aqrAccept;
		else if (QuerySetting() == 4)
			verifiedHost = vncServer::aqrReject;
		break;
	case vncServer::aqrReject:
		if (QuerySetting() == 0)
			verifiedHost = vncServer::aqrQuery;
		break;
	};

	return verifiedHost;
}

void
vncServer::AddAuthHostsBlacklist(const char *machine) {
	omni_mutex_lock l(m_clientsLock);

	// -=- Is the specified host blacklisted?
	vncServer::BlacklistEntry	*current = m_blacklist;

	// Get the current time as a 64-bit value
	SYSTEMTIME					systime;
	FILETIME					ftime;
	LARGE_INTEGER				now;
	GetSystemTime(&systime);
	SystemTimeToFileTime(&systime, &ftime);
	now.LowPart=ftime.dwLowDateTime;now.HighPart=ftime.dwHighDateTime;
	now.QuadPart /= 10000000; // Convert it into seconds

	while (current) {

		// Is this the entry we're interested in?
		if (strcmp(current->_machineName, machine) == 0) {

			// If the host is already blocked then ignore
			if (current->_blocked)
				return;

			// Set the RefTime & failureCount
			current->_lastRefTime.QuadPart = now.QuadPart + 10;
			current->_failureCount++;

			if (current->_failureCount > 5)
				current->_blocked = TRUE;
			return;
		}

		current = current->_next;
	}

	// Didn't find the entry
	current = new vncServer::BlacklistEntry;
	current->_blocked = FALSE;
	current->_failureCount = 0;
	current->_lastRefTime.QuadPart = now.QuadPart + 10;
	current->_machineName = strdup(machine);
	current->_next = m_blacklist;
	m_blacklist = current;
}

void
vncServer::RemAuthHostsBlacklist(const char *machine) {
	omni_mutex_lock l(m_clientsLock);

	// -=- Is the specified host blacklisted?
	vncServer::BlacklistEntry	*current = m_blacklist;
	vncServer::BlacklistEntry	*previous = 0;

	while (current) {

		// Is this the entry we're interested in?
		if (strcmp(current->_machineName, machine) == 0) {
			if (previous)
				previous->_next = current->_next;
			else
				m_blacklist = current->_next;
			vncServer::BlacklistEntry *next = current->_next;
			free (current->_machineName);
			delete current;
			current = next;
			continue;
		}

		previous = current;
		current = current->_next;
	}
}

void
vncServer::SetWindowShared(HWND hWnd)
{
	m_hwndShared=hWnd;
}

void  vncServer::SetMatchSizeFields(int left,int top,int right,int bottom)
{
	RECT trect = GetScreenRect();

/*	if ( right - left < 32 )
		right = left + 32;
	
	if ( bottom - top < 32)
		bottom = top + 32 ;*/

	if( right > trect.right )
		right = trect.right;
	if( bottom > trect.bottom )
		bottom = trect.bottom;
	if( left < trect.left)
		left = trect.left;
	if( top < trect.top)
		top = trect.top;

 
	m_screenarea_rect.left=left;
	m_screenarea_rect.top=top;
	m_screenarea_rect.bottom=bottom;
	m_screenarea_rect.right=right;
}


void 
vncServer::SetKeyboardCounter(int count)
{
		
	omni_mutex_lock l(m_clientsLock);
	if (LocalInputPriority() && vncService::IsWin95())
	{
		m_remote_keyboard += count;
		if (count == 0)
			m_remote_keyboard = 0;
	}       
	
}

void 
vncServer::SetMouseCounter(int count, POINT &cursor_pos, BOOL mousemove)
{
	if( (mousemove) && ( abs (m_cursor_pos.x - cursor_pos.x)==0 
		&&  abs (m_cursor_pos.y - cursor_pos.y)==0 ) ) 
		return;
	
	omni_mutex_lock l(m_clientsLock);
	if (LocalInputPriority() && vncService::IsWin95())
	{
		m_remote_mouse += count;
		if (count == 0)
			m_remote_mouse = 0;

		m_cursor_pos.x = cursor_pos.x;
		m_cursor_pos.y = cursor_pos.y;
		
	
	}
	
}

void 
vncServer::SetNewFBSize(BOOL sendnewfb)
{
	vncClientList::iterator i;
	omni_mutex_lock l(m_clientsLock);

	// Post new framebuffer size update to all the connected clients
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		// Post the update
		GetClient(*i)->SetNewFBSize( sendnewfb);
	}
}


BOOL 
vncServer::FullRgnRequested()
{
	vncClientList::iterator i;
	omni_mutex_lock l(m_clientsLock);

	// Iterate over the authorised clients
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		if (GetClient(*i)->FullRgnRequested())
			return TRUE;
	}
	return FALSE;
}

BOOL 
vncServer::IncrRgnRequested()
{
	vncClientList::iterator i;
	omni_mutex_lock l(m_clientsLock);

	// Iterate over the authorised clients
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		if (GetClient(*i)->IncrRgnRequested())
			return TRUE;
	}
	return FALSE;
}

void 
vncServer::UpdateLocalFormat()
{
	vncClientList::iterator i;
	omni_mutex_lock l(m_clientsLock);

	// Iterate over the authorised clients
	for (i = m_authClients.begin(); i != m_authClients.end(); i++)
	{
		GetClient(*i)->UpdateLocalFormat();
			
	}
	return;
}

void 
vncServer::SetPollingCycle(UINT msec)
{
	if (m_polling_cycle != msec && msec > 10) {
		m_polling_cycle = msec;
		PollingCycleChanged(true);
	}
}

BOOL
vncServer::checkPointer(vncClient *pClient)
{
  vncClientList::iterator i;
  for (i = m_authClients.begin(); i != m_authClients.end(); i++)
  {
    if (GetClient(*i) == pClient) return TRUE;
  }
  return FALSE;
}

BOOL
vncServer::DriverActive() {
	return (m_desktop != NULL) ? m_desktop->DriverActive() : FALSE;
}

typedef HMONITOR (WINAPI* pMonitorFromPoint)(POINT,DWORD);
typedef BOOL (WINAPI* pGetMonitorInfo)(HMONITOR,LPMONITORINFO);

BOOL vncServer::SetShareMonitorFromPoint(POINT pt)
{
	HINSTANCE  hInstUser32 = LoadLibrary("User32.DLL");
	if (!hInstUser32) return FALSE;  
	pMonitorFromPoint pMFP = (pMonitorFromPoint)GetProcAddress(hInstUser32, "MonitorFromPoint");
	pGetMonitorInfo pGMI = (pGetMonitorInfo)GetProcAddress(hInstUser32, "GetMonitorInfoA");
	if (!pMFP || !pGMI)
	{
		FreeLibrary(hInstUser32);
		return FALSE;
	}

	HMONITOR hm = pMFP(pt, MONITOR_DEFAULTTONEAREST);
	if (!hm)
	{
		FreeLibrary(hInstUser32);
		return FALSE;
	}
	MONITORINFO	moninfo;
	moninfo.cbSize = sizeof(moninfo);
	if (!pGMI(hm, &moninfo))
	{
		FreeLibrary(hInstUser32);
		return FALSE;
	}

	FullScreen(FALSE);
	WindowShared(FALSE);
	ScreenAreaShared(TRUE);
	PrimaryDisplayOnlyShared(FALSE);

	SetMatchSizeFields(
		moninfo.rcMonitor.left,
		moninfo.rcMonitor.top,
		moninfo.rcMonitor.right,
		moninfo.rcMonitor.bottom);

	FreeLibrary(hInstUser32);
	return TRUE;
}
