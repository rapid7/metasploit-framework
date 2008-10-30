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


// vncClient.cpp

// The per-client object.  This object takes care of all per-client stuff,
// such as socket input and buffering of updates.

// vncClient class handles the following functions:
// - Recieves requests from the connected client and
//   handles them
// - Handles incoming updates properly, using a vncBuffer
//   object to keep track of screen changes
// It uses a vncBuffer and is passed the vncDesktop and
// vncServer to communicate with.

// Includes
#include "stdhdrs.h"
#include <omnithread.h>
#include "resource.h"

// Custom
#include "vncServer.h"
#include "vncClient.h"
#include "VSocket.h"
#include "vncDesktop.h"
#include "rfbRegion.h"
#include "vncBuffer.h"
#include "vncService.h"
#include "vncPasswd.h"
#include "vncAcceptDialog.h"
#include "vncKeymap.h"

// #include "rfb.h"

// vncClient update thread class

class vncClientUpdateThread : public omni_thread
{
public:

	// Init
	BOOL Init(vncClient *client);

	// Kick the thread to send an update
	void Trigger();

	// Kill the thread
	void Kill();

	// Disable/enable updates
	void EnableUpdates(BOOL enable);

	// The main thread function
  virtual void *run_undetached(void *arg);

protected:
	virtual ~vncClientUpdateThread();

	// Fields
protected:
	vncClient *m_client;
	omni_condition *m_signal;
	omni_condition *m_sync_sig;
	BOOL m_active;
	BOOL m_enable;
};

BOOL
vncClientUpdateThread::Init(vncClient *client)
{
	//vnclog.Print(LL_INTINFO, VNCLOG("init update thread\n"));

	m_client = client;
	omni_mutex_lock l(m_client->GetUpdateLock());
	m_signal = new omni_condition(&m_client->GetUpdateLock());
	m_sync_sig = new omni_condition(&m_client->GetUpdateLock());
	m_active = TRUE;
	m_enable = m_client->m_disable_protocol == 0;
	if (m_signal && m_sync_sig) {
		start_undetached();
		return TRUE;
	}
	return FALSE;
}

vncClientUpdateThread::~vncClientUpdateThread()
{
	if (m_signal) delete m_signal;
	if (m_sync_sig) delete m_sync_sig;
	//vnclog.Print(LL_INTINFO, VNCLOG("update thread gone\n"));
}

void
vncClientUpdateThread::Trigger()
{
	// ALWAYS lock client UpdateLock before calling this!
	// Only trigger an update if protocol is enabled
	if (m_client->m_disable_protocol == 0) {
		m_signal->signal();
	}
}

void
vncClientUpdateThread::Kill()
{
	//vnclog.Print(LL_INTINFO, VNCLOG("kill update thread\n"));

	omni_mutex_lock l(m_client->GetUpdateLock());
	m_active=FALSE;
	m_signal->signal();
}

void
vncClientUpdateThread::EnableUpdates(BOOL enable)
{
	// ALWAYS call this with the UpdateLock held!
	//if (enable) {
	//	//vnclog.Print(LL_INTINFO, VNCLOG("enable update thread\n"));
	//} else {
	//	//vnclog.Print(LL_INTINFO, VNCLOG("disable update thread\n"));
	//}

	m_enable = enable;
	m_signal->signal();
	m_sync_sig->wait();
	//vnclog.Print(LL_INTINFO, VNCLOG("enable/disable synced\n"));
}

void*
vncClientUpdateThread::run_undetached(void *arg)
{
	rfb::SimpleUpdateTracker update;
	rfb::Region2D clipregion;
	char *clipboard_text = 0;
	update.enable_copyrect(true);
	BOOL send_palette = FALSE;

	unsigned long updates_sent=0;

	//vnclog.Print(LL_INTINFO, VNCLOG("starting update thread\n"));

	// Set client update threads to high priority
	// *** set_priority(omni_thread::PRIORITY_HIGH);

	while (1)
	{
		// Block waiting for an update to send
		{
			omni_mutex_lock l(m_client->GetUpdateLock());
			m_client->m_incr_rgn = m_client->m_incr_rgn.union_(clipregion);

			// We block as long as updates are disabled, or the client
			// isn't interested in them, unless this thread is killed.
			while (m_active && (
						!m_enable || (
							m_client->m_update_tracker.get_changed_region().intersect(m_client->m_incr_rgn).is_empty() &&
							m_client->m_update_tracker.get_copied_region().intersect(m_client->m_incr_rgn).is_empty() &&
							!m_client->m_clipboard_text
							)
						)
					) {
				// Issue the synchronisation signal, to tell other threads
				// where we have got to
				m_sync_sig->broadcast();

				// Wait to be kicked into action
				m_signal->wait();
			}

			// If the thread is being killed then quit
			if (!m_active) break;

			// SEND AN UPDATE!
			// The thread is active, updates are enabled, and the
			// client is expecting an update - let's see if there
			// is anything to send.

			// Has the palette changed?
			send_palette = m_client->m_palettechanged;
			m_client->m_palettechanged = FALSE;

			// Fetch the incremental region
			clipregion = m_client->m_incr_rgn;
			m_client->m_incr_rgn.clear();

			// Get the clipboard data, if any
			if (m_client->m_clipboard_text) {
				clipboard_text = m_client->m_clipboard_text;
				m_client->m_clipboard_text = 0;
			}

			// Get the update details from the update tracker
			m_client->m_update_tracker.flush_update(update, clipregion);

			// Render the mouse if required
			if (m_client->m_mousemoved)
			{
				// Re-render its old location
				m_client->m_oldmousepos =
					m_client->m_oldmousepos.intersect(m_client->m_fullscreen);
				if (!m_client->m_oldmousepos.is_empty())
					update.add_changed(m_client->m_oldmousepos);

				// And render its new one
				m_client->m_encodemgr.m_buffer->GetMousePos(m_client->m_oldmousepos);
				m_client->m_oldmousepos =
					m_client->m_oldmousepos.intersect(m_client->m_fullscreen);
				if (!m_client->m_oldmousepos.is_empty())
					update.add_changed(m_client->m_oldmousepos);

				m_client->m_mousemoved = FALSE;
			}

			// Get the encode manager to update the client back buffer
			m_client->m_encodemgr.GrabRegion(update.get_changed_region());
		}

		// SEND THE CLIPBOARD
		// If there is clipboard text to be sent then send it
		if (clipboard_text) {
			rfbServerCutTextMsg message;

			message.length = Swap32IfLE(strlen(clipboard_text));
			if (!m_client->SendRFBMsg(rfbServerCutText,
				(BYTE *) &message, sizeof(message))) {
				m_client->m_socket->Close();
			}
			if (!m_client->m_socket->SendExact(clipboard_text, strlen(clipboard_text)))
			{
				m_client->m_socket->Close();
			}
			free(clipboard_text);
			clipboard_text = 0;
		}

		// SEND AN UPDATE
		// We do this without holding locks, to avoid network problems
		// stalling the server.

		// Update the client palette if necessary
		if (send_palette) {
			m_client->SendPalette();
		}

		// Send updates to the client - this implicitly clears
		// the supplied update tracker
		if (m_client->SendUpdate(update)) {
			updates_sent++;
			clipregion.clear();
		}
	}

	//vnclog.Print(LL_INTINFO, VNCLOG("stopping update thread\n"));
	
	//vnclog.Print(LL_INTERR, "client sent %lu updates\n", updates_sent);
	return 0;
}

// vncClient thread class

class vncClientThread : public omni_thread
{
public:

	// Init
	virtual BOOL Init(vncClient *client,
		vncServer *server,
		VSocket *socket,
		BOOL auth,
		BOOL shared);

	// Sub-Init routines
	virtual BOOL InitVersion();
	virtual BOOL InitAuthenticate();

	// The main thread function
	virtual void run(void *arg);

protected:
	virtual ~vncClientThread();

	// Fields
protected:
	VSocket *m_socket;
	vncServer *m_server;
	vncClient *m_client;
	BOOL m_auth;
	BOOL m_shared;
};

vncClientThread::~vncClientThread()
{
	// If we have a client object then delete it
	if (m_client != NULL)
		delete m_client;
}

BOOL
vncClientThread::Init(vncClient *client, vncServer *server, VSocket *socket, BOOL auth, BOOL shared)
{
	// Save the server pointer and window handle
	m_server = server;
	m_socket = socket;
	m_client = client;
	m_auth = auth;
	m_shared = shared;

	// Start the thread
	start();

	return TRUE;
}

BOOL
vncClientThread::InitVersion()
{
	// Generate the server's protocol version
	rfbProtocolVersionMsg protocolMsg;
	sprintf((char *)protocolMsg,
		rfbProtocolVersionFormat,
		rfbProtocolMajorVersion,
		rfbProtocolMinorVersion);

	// Send the protocol message
	if (!m_socket->SendExact((char *)&protocolMsg, sz_rfbProtocolVersionMsg))
		return FALSE;

	// Now, get the client's protocol version
	rfbProtocolVersionMsg protocol_ver;
	protocol_ver[12] = 0;
	if (!m_socket->ReadExact((char *)&protocol_ver, sz_rfbProtocolVersionMsg))
		return FALSE;

	// Check the protocol version
	int major, minor;
	sscanf((char *)&protocol_ver, rfbProtocolVersionFormat, &major, &minor);
	if (major != rfbProtocolMajorVersion)
		return FALSE;

	return TRUE;
}

BOOL
vncClientThread::InitAuthenticate()
{
	// Retrieve the local password
	char password[MAXPWLEN];
	m_server->GetPassword(password);
	vncPasswd::ToText plain(password);

	/*

	// Verify the peer host name against the AuthHosts string
	vncServer::AcceptQueryReject verified;
	if (m_auth) {
		verified = vncServer::aqrAccept;
	} else {
		verified = m_server->VerifyHost(m_socket->GetPeerName());
	}
	
	// If necessary, query the connection with a timed dialog
	if (verified == vncServer::aqrQuery) {
		vncAcceptDialog *acceptDlg = new vncAcceptDialog(m_server->QueryTimeout(), m_socket->GetPeerName());
		if ((acceptDlg == 0) || (!(acceptDlg->DoDialog())))
			verified = vncServer::aqrReject;
	}
	if (verified == vncServer::aqrReject) {
		CARD32 auth_val = Swap32IfLE(rfbConnFailed);
		char *errmsg = "Your connection has been rejected.";
		CARD32 errlen = Swap32IfLE(strlen(errmsg));
		if (!m_socket->SendExact((char *)&auth_val, sizeof(auth_val)))
			return FALSE;
		if (!m_socket->SendExact((char *)&errlen, sizeof(errlen)))
			return FALSE;
		m_socket->SendExact(errmsg, strlen(errmsg));
		return FALSE;
	}

	
	// By default we disallow passwordless workstations!
	if ((strlen(plain) == 0) && m_server->AuthRequired())
	{
		//vnclog.Print(LL_CONNERR, VNCLOG("no password specified for server - client rejected\n"));

		// Send an error message to the client
		CARD32 auth_val = Swap32IfLE(rfbConnFailed);
		char *errmsg =
			"This server does not have a valid password enabled.  "
			"Until a password is set, incoming connections cannot be accepted.";
		CARD32 errlen = Swap32IfLE(strlen(errmsg));

		if (!m_socket->SendExact((char *)&auth_val, sizeof(auth_val)))
			return FALSE;
		if (!m_socket->SendExact((char *)&errlen, sizeof(errlen)))
			return FALSE;
		m_socket->SendExact(errmsg, strlen(errmsg));

		return FALSE;
	}
	*/

	// By default we filter out local loop connections, because they're pointless
/*
 * if (!m_server->LoopbackOk())
	{
		char *localname = strdup(m_socket->GetSockName());
		char *remotename = strdup(m_socket->GetPeerName());

		// Check that the local & remote names are different!
		if ((localname != NULL) && (remotename != NULL))
		{
			BOOL ok = strcmp(localname, remotename) != 0;

			if (localname != NULL)
				free(localname);

			if (remotename != NULL)
				free(remotename);

			if (!ok)
			{
				//vnclog.Print(LL_CONNERR, VNCLOG("loopback connection attempted - client rejected\n"));
				
				// Send an error message to the client
				CARD32 auth_val = Swap32IfLE(rfbConnFailed);
				char *errmsg = "Local loop-back connections are disabled.";
				CARD32 errlen = Swap32IfLE(strlen(errmsg));

				if (!m_socket->SendExact((char *)&auth_val, sizeof(auth_val)))
					return FALSE;
				if (!m_socket->SendExact((char *)&errlen, sizeof(errlen)))
					return FALSE;
				m_socket->SendExact(errmsg, strlen(errmsg));

				return FALSE;
			}
		}
	}
*/

	// Authenticate the connection, if required
	if (m_auth || (strlen(plain) == 0))
	{
		// Send no-auth-required message
		CARD32 auth_val = Swap32IfLE(rfbNoAuth);
		if (!m_socket->SendExact((char *)&auth_val, sizeof(auth_val)))
			return FALSE;
	}
	else
	{
		// Send auth-required message
		CARD32 auth_val = Swap32IfLE(rfbVncAuth);
		if (!m_socket->SendExact((char *)&auth_val, sizeof(auth_val)))
			return FALSE;

		BOOL auth_ok = TRUE;
		{
			// Now create a 16-byte challenge
			char challenge[16];
			vncRandomBytes((BYTE *)&challenge);

			// Send the challenge to the client
			if (!m_socket->SendExact(challenge, sizeof(challenge)))
				return FALSE;

			// Read the response
			char response[16];
			if (!m_socket->ReadExact(response, sizeof(response)))\
				return FALSE;

			// Encrypt the challenge bytes
			vncEncryptBytes((BYTE *)&challenge, plain);

			// Compare them to the response
			for (int i=0; i<sizeof(challenge); i++)
			{
				if (challenge[i] != response[i])
				{
					auth_ok = FALSE;
					break;
				}
			}
		}

		// Did the authentication work?
		CARD32 authmsg;
		if (!auth_ok)
		{
			//vnclog.Print(LL_CONNERR, VNCLOG("authentication failed\n"));

			authmsg = Swap32IfLE(rfbVncAuthFailed);
			m_socket->SendExact((char *)&authmsg, sizeof(authmsg));
			return FALSE;
		}
		else
		{
			// Tell the client we're ok
			authmsg = Swap32IfLE(rfbVncAuthOK);
			if (!m_socket->SendExact((char *)&authmsg, sizeof(authmsg)))
				return FALSE;
		}
	}

	// Read the client's initialisation message
	rfbClientInitMsg client_ini;
	if (!m_socket->ReadExact((char *)&client_ini, sz_rfbClientInitMsg))
		return FALSE;

	// If the client wishes to have exclusive access then remove other clients
	if (!client_ini.shared && !m_shared)
	{
		// Which client takes priority, existing or incoming?
		if (m_server->ConnectPriority() < 1)
		{
			// Incoming
			//vnclog.Print(LL_INTINFO, VNCLOG("non-shared connection - disconnecting old clients\n"));
			m_server->KillAuthClients();
		} else if (m_server->ConnectPriority() > 1)
		{
			// Existing
			if (m_server->AuthClientCount() > 0)
			{
				//vnclog.Print(LL_CLIENTS, VNCLOG("connections already exist - client rejected\n"));
				return FALSE;
			}
		}
	}

	// Tell the server that this client is ok
	return m_server->Authenticated(m_client->GetClientId());
}

void
ClearKeyState(BYTE key)
{
	// This routine is used by the VNC client handler to clear the
	// CAPSLOCK, NUMLOCK and SCROLL-LOCK states.

	BYTE keyState[256];
	
	GetKeyboardState((LPBYTE)&keyState);

	if(keyState[key] & 1)
	{
		// Simulate the key being pressed
		keybd_event(key, 0, KEYEVENTF_EXTENDEDKEY, 0);

		// Simulate it being release
		keybd_event(key, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0);
	}
}

void
vncClientThread::run(void *arg)
{
	// All this thread does is go into a socket-recieve loop,
	// waiting for stuff on the given socket

	// IMPORTANT : ALWAYS call RemoveClient on the server before quitting
	// this thread.

	//vnclog.Print(LL_CLIENTS, VNCLOG("client connected : %s (%hd)\n"),
	//							m_client->GetClientName(),
	//							m_client->GetClientId());

	// Save the handle to the thread's original desktop
	HDESK home_desktop = GetThreadDesktop(GetCurrentThreadId());
	
	// To avoid people connecting and then halting the connection, set a timeout
	m_socket->SetTimeout(30000);
	//if (!m_socket->SetTimeout(30000))
		//vnclog.Print(LL_INTERR, VNCLOG("failed to set socket timeout(%d)\n"), GetLastError());

	// Initially blacklist the client so that excess connections from it get dropped
	m_server->AddAuthHostsBlacklist(m_client->GetClientName());

	// LOCK INITIAL SETUP
	// All clients have the m_protocol_ready flag set to FALSE initially, to prevent
	// updates and suchlike interfering with the initial protocol negotiations.

	// GET PROTOCOL VERSION
	if (!InitVersion())
	{
		m_server->RemoveClient(m_client->GetClientId());
		return;
	}
	//vnclog.Print(LL_INTINFO, VNCLOG("negotiated version\n"));

	// AUTHENTICATE LINK
	if (!InitAuthenticate())
	{
		m_server->RemoveClient(m_client->GetClientId());
		return;
	}

	// Authenticated OK - remove from blacklist and remove timeout
	m_server->RemAuthHostsBlacklist(m_client->GetClientName());
	m_socket->SetTimeout(m_server->AutoIdleDisconnectTimeout()*1000);
	//vnclog.Print(LL_INTINFO, VNCLOG("authenticated connection\n"));

	// INIT PIXEL FORMAT

	// Get the screen format
	m_client->m_fullscreen = m_client->m_encodemgr.GetSize();


	char desktopname[MAX_COMPUTERNAME_LENGTH+256+32+1];

	// Get our current user name
	char uid[256];
	DWORD uidsz = sizeof(uid);
	GetUserName(uid, &uidsz);

	// Get the name of this system
	DWORD sysnamelen = MAX_COMPUTERNAME_LENGTH + 1;
	char sysname[MAX_COMPUTERNAME_LENGTH+1];
	GetComputerName(sysname, &sysnamelen);
	
	// Do we have write access to the desktop? Easy test...
	DWORD dummy;
	char name_win[256];
	HWINSTA os = GetProcessWindowStation();
	GetUserObjectInformation(os,   UOI_NAME, &name_win, 256, &dummy);
	
	int x;
	char *access = "Full Access";
	for (x=0; x<strlen(name_win); x++) {
		name_win[x] = tolower(name_win[x]);
	}
	if (strcmp(name_win, "winsta0") != 0) {
		access = "Read Only";
	}
	_snprintf(desktopname, sizeof(desktopname)-1, "VNCShell [%s@%s] - %s", uid, sysname, access);

	// Send the server format message to the client
	rfbServerInitMsg server_ini;
	server_ini.format = m_client->m_encodemgr.m_buffer->GetLocalFormat();

	// Endian swaps
	server_ini.framebufferWidth = Swap16IfLE(m_client->m_fullscreen.br.x);
	server_ini.framebufferHeight = Swap16IfLE(m_client->m_fullscreen.br.y);
	server_ini.format.redMax = Swap16IfLE(server_ini.format.redMax);
	server_ini.format.greenMax = Swap16IfLE(server_ini.format.greenMax);
	server_ini.format.blueMax = Swap16IfLE(server_ini.format.blueMax);

	server_ini.nameLength = Swap32IfLE(strlen(desktopname));
	if (!m_socket->SendExact((char *)&server_ini, sizeof(server_ini)))
	{
		m_server->RemoveClient(m_client->GetClientId());
		return;
	}
	if (!m_socket->SendExact(desktopname, strlen(desktopname)))
	{
		m_server->RemoveClient(m_client->GetClientId());
		return;
	}
	//vnclog.Print(LL_INTINFO, VNCLOG("sent pixel format to client\n"));

	// UNLOCK INITIAL SETUP
	// Initial negotiation is complete, so set the protocol ready flag
	m_client->EnableProtocol();
	
	// Add a fullscreen update to the client's update list
  { omni_mutex_lock l(m_client->GetUpdateLock());
	  m_client->m_update_tracker.add_changed(m_client->m_fullscreen);
  }

	// Clear the CapsLock and NumLock keys
	if (m_client->m_keyboardenabled)
	{
		ClearKeyState(VK_CAPITAL);
		// *** JNW - removed because people complain it's wrong
		//ClearKeyState(VK_NUMLOCK);
		ClearKeyState(VK_SCROLL);
	}

	// MAIN LOOP

	// Set the input thread to a high priority
	set_priority(omni_thread::PRIORITY_HIGH);

	BOOL connected = TRUE;
	while (connected)
	{
		rfbClientToServerMsg msg;

		// Ensure that we're running in the correct desktop
		if (!vncService::InputDesktopSelected())
			if (!vncService::SelectDesktop(NULL))
				break;

		// Try to read a message ID
		if (!m_socket->ReadExact((char *)&msg.type, sizeof(msg.type)))
		{
			connected = FALSE;
			break;
		}

		// What to do is determined by the message id
		switch(msg.type)
		{

		case rfbSetPixelFormat:
			// Read the rest of the message:
			if (!m_socket->ReadExact(((char *) &msg)+1, sz_rfbSetPixelFormatMsg-1))
			{
				connected = FALSE;
				break;
			}

			// Swap the relevant bits.
			msg.spf.format.redMax = Swap16IfLE(msg.spf.format.redMax);
			msg.spf.format.greenMax = Swap16IfLE(msg.spf.format.greenMax);
			msg.spf.format.blueMax = Swap16IfLE(msg.spf.format.blueMax);

			// Prevent updates while the pixel format is changed
			m_client->DisableProtocol();
				
			// Tell the buffer object of the change			
			if (!m_client->m_encodemgr.SetClientFormat(msg.spf.format))
			{
				//vnclog.Print(LL_CONNERR, VNCLOG("remote pixel format invalid\n"));

				connected = FALSE;
			}

			// Set the palette-changed flag, just in case...
			m_client->m_palettechanged = TRUE;

			// Re-enable updates
			m_client->EnableProtocol();
			
			break;

		case rfbSetEncodings:
			// Read the rest of the message:
			if (!m_socket->ReadExact(((char *) &msg)+1, sz_rfbSetEncodingsMsg-1))
			{
				connected = FALSE;
				break;
			}

			// Prevent updates while the encoder is changed
			m_client->DisableProtocol();

			// Read in the preferred encodings
			msg.se.nEncodings = Swap16IfLE(msg.se.nEncodings);
			{
				int x;
				BOOL encoding_set = FALSE;

				// By default, don't use copyrect!
				m_client->m_update_tracker.enable_copyrect(false);

				for (x=0; x<msg.se.nEncodings; x++)
				{
					CARD32 encoding;

					// Read an encoding in
					if (!m_socket->ReadExact((char *)&encoding, sizeof(encoding)))
					{
						connected = FALSE;
						break;
					}

					// Is this the CopyRect encoding (a special case)?
					if (Swap32IfLE(encoding) == rfbEncodingCopyRect)
					{
						m_client->m_update_tracker.enable_copyrect(true);
						continue;
					}

					// Have we already found a suitable encoding?
					if (!encoding_set)
					{
						// No, so try the buffer to see if this encoding will work...
						if (m_client->m_encodemgr.SetEncoding(Swap32IfLE(encoding)))
							encoding_set = TRUE;
					}
				}

				// If no encoding worked then default to RAW!
				if (!encoding_set)
				{
					//vnclog.Print(LL_INTINFO, VNCLOG("defaulting to raw encoder\n"));

					if (!m_client->m_encodemgr.SetEncoding(Swap32IfLE(rfbEncodingRaw)))
					{
						//vnclog.Print(LL_INTERR, VNCLOG("failed to select raw encoder!\n"));

						connected = FALSE;
					}
				}
			}

			// Re-enable updates
			m_client->EnableProtocol();

			break;
			
		case rfbFramebufferUpdateRequest:
			// Read the rest of the message:
			if (!m_socket->ReadExact(((char *) &msg)+1, sz_rfbFramebufferUpdateRequestMsg-1))
			{
				connected = FALSE;
				break;
			}

			{
				rfb::Rect update;

				// Get the specified rectangle as the region to send updates for.
				update.tl.x = Swap16IfLE(msg.fur.x);
				update.tl.y = Swap16IfLE(msg.fur.y);
				update.br.x = update.tl.x + Swap16IfLE(msg.fur.w);
				update.br.y = update.tl.y + Swap16IfLE(msg.fur.h);
				rfb::Region2D update_rgn = update;
        if (update_rgn.is_empty()) {
          //vnclog.Print(LL_INTERR, VNCLOG("FATAL! client update region is empty!\n"));
          connected = FALSE;
          break;
        }

				{	omni_mutex_lock l(m_client->GetUpdateLock());

					// Add the requested area to the incremental update cliprect
					m_client->m_incr_rgn = m_client->m_incr_rgn.union_(update_rgn);

					// Is this request for a full update?
					if (!msg.fur.incremental)
					{
						// Yes, so add the region to the update tracker
						m_client->m_update_tracker.add_changed(update_rgn);

						// Tell the desktop grabber to fetch the region's latest state
						m_client->m_encodemgr.m_buffer->m_desktop->QueueRect(update);
					}

          // Kick the update thread (and create it if not there already)
					m_client->TriggerUpdateThread();
				}
			}
			break;

		case rfbKeyEvent:
			// Read the rest of the message:
			if (m_socket->ReadExact(((char *) &msg)+1, sz_rfbKeyEventMsg-1))
			{				
				if (m_client->m_keyboardenabled)
				{
					msg.ke.key = Swap32IfLE(msg.ke.key);

					// Get the keymapper to do the work
					vncKeymap::keyEvent(msg.ke.key, msg.ke.down);

					m_client->m_remoteevent = TRUE;
				}
			}
			break;

		case rfbPointerEvent:
			// Read the rest of the message:
			if (m_socket->ReadExact(((char *) &msg)+1, sz_rfbPointerEventMsg-1))
			{
				if (m_client->m_pointerenabled)
				{
					// Convert the coords to Big Endian
					msg.pe.x = Swap16IfLE(msg.pe.x);
					msg.pe.y = Swap16IfLE(msg.pe.y);

					// Work out the flags for this event
					DWORD flags = MOUSEEVENTF_ABSOLUTE;
          long data = 0;
					if (msg.pe.x != m_client->m_ptrevent.x ||
						msg.pe.y != m_client->m_ptrevent.y)
						flags |= MOUSEEVENTF_MOVE;
					if ( (msg.pe.buttonMask & rfbButton1Mask) != 
						(m_client->m_ptrevent.buttonMask & rfbButton1Mask) )
					{
					    if (GetSystemMetrics(SM_SWAPBUTTON))
						flags |= (msg.pe.buttonMask & rfbButton1Mask) 
						    ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
					    else
						flags |= (msg.pe.buttonMask & rfbButton1Mask) 
						    ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
					}
					if ( (msg.pe.buttonMask & rfbButton2Mask) != 
						(m_client->m_ptrevent.buttonMask & rfbButton2Mask) )
					{
						flags |= (msg.pe.buttonMask & rfbButton2Mask) 
						    ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
					}
					if ( (msg.pe.buttonMask & rfbButton3Mask) != 
						(m_client->m_ptrevent.buttonMask & rfbButton3Mask) )
					{
					    if (GetSystemMetrics(SM_SWAPBUTTON))
						flags |= (msg.pe.buttonMask & rfbButton3Mask) 
						    ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
					    else
						flags |= (msg.pe.buttonMask & rfbButton3Mask) 
						    ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
					}

          // Mouse wheel support
          if (msg.pe.buttonMask & rfbWheelUpMask) {
            flags |= MOUSEEVENTF_WHEEL;
            data = WHEEL_DELTA;
          }
          if (msg.pe.buttonMask & rfbWheelDownMask) {
            flags |= MOUSEEVENTF_WHEEL;
            data = -WHEEL_DELTA;
          }

					// Generate coordinate values
					unsigned long x = (msg.pe.x *  65535) / (m_client->m_fullscreen.br.x);
					unsigned long y = (msg.pe.y * 65535) / (m_client->m_fullscreen.br.y);

					// Do the pointer event
					::mouse_event(flags, (DWORD) x, (DWORD) y, data, 0);

					// Save the old position
					m_client->m_ptrevent = msg.pe;

					// Flag that a remote event occurred
					m_client->m_remoteevent = TRUE;

					// Tell the desktop hook system to grab the screen...
					m_client->m_encodemgr.m_buffer->m_desktop->TriggerUpdate();
				}
			}
			
			break;

		case rfbClientCutText:
			// Read the rest of the message:
			if (m_socket->ReadExact(((char *) &msg)+1, sz_rfbClientCutTextMsg-1))
			{
				// Allocate storage for the text
				const UINT length = Swap32IfLE(msg.cct.length);
				char *text = new char [length+1];
				if (text == NULL)
					break;
				text[length] = 0;

				// Read in the text
				if (!m_socket->ReadExact(text, length)) {
					delete [] text;
					break;
				}

				// Get the server to update the local clipboard
				m_server->UpdateLocalClipText(text);

				// Free the clip text we read
				delete [] text;
			}
			break;

		default:
			// Unknown message, so fail!
			connected = FALSE;
		}
	}
		
	// Move into the thread's original desktop
	vncService::SelectHDESK(home_desktop);

	// Quit this thread.  This will automatically delete the thread and the
	// associated client.
	//vnclog.Print(LL_CLIENTS, VNCLOG("client disconnected : %s (%hd)\n"),
	//								m_client->GetClientName(),
	//								m_client->GetClientId());


	// Disable the protocol to ensure that the update thread
	// is not accessing the desktop and buffer objects
	m_client->DisableProtocol();

	// Finally, it's safe to kill the update thread here
	if (m_client->m_updatethread) {
		m_client->m_updatethread->Kill();
		m_client->m_updatethread->join(NULL);
	}

	// Remove the client from the server
	// This may result in the desktop and buffer being destroyed
	// It also guarantees that the client will not be passed further
	// updates
	m_server->RemoveClient(m_client->GetClientId());

}

// The vncClient itself

vncClient::vncClient()
{
	//vnclog.Print(LL_INTINFO, VNCLOG("vncClient() executing...\n"));

	m_socket = NULL;
	m_client_name = 0;

	// Initialise mouse fields
	m_mousemoved = FALSE;
	m_ptrevent.buttonMask = 0;
	m_ptrevent.x = 0;
	m_ptrevent.y=0;

	// Other misc flags
	m_thread = NULL;
	m_palettechanged = FALSE;

	// Initialise the two update stores
	m_updatethread = NULL;
	m_update_tracker.init(this);

	m_remoteevent = FALSE;

	m_clipboard_text = 0;

	// IMPORTANT: Initially, client is not protocol-ready.
	m_disable_protocol = 1;
}

vncClient::~vncClient()
{
	//vnclog.Print(LL_INTINFO, VNCLOG("~vncClient() executing...\n"));

	// We now know the thread is dead, so we can clean up
	if (m_client_name != 0) {
		free(m_client_name);
		m_client_name = 0;
	}

	// If we have a socket then kill it
	if (m_socket != NULL)
	{
		//vnclog.Print(LL_INTINFO, VNCLOG("deleting socket\n"));

		delete m_socket;
		m_socket = NULL;
	}
}

// Init
BOOL
vncClient::Init(vncServer *server,
				VSocket *socket,
				BOOL auth,
				BOOL shared,
				vncClientId newid)
{
	// Save the server id;
	m_server = server;

	// Save the socket
	m_socket = socket;

	// Save the name of the connecting client
	char *name = m_socket->GetPeerName();
	if (name != 0)
		m_client_name = strdup(name);
	else
		m_client_name = strdup("<unknown>");

	// Save the client id
	m_id = newid;

	// Spawn the child thread here
	m_thread = new vncClientThread;
	if (m_thread == NULL)
		return FALSE;
	return ((vncClientThread *)m_thread)->Init(this, m_server, m_socket, auth, shared);

	return FALSE;
}

void
vncClient::Kill()
{
	// Close the socket
	//vnclog.Print(LL_INTERR, VNCLOG("client Kill() called"));
	if (m_socket != NULL)
		m_socket->Close();
}

// Client manipulation functions for use by the server
void
vncClient::SetBuffer(vncBuffer *buffer)
{
	// Until authenticated, the client object has no access
	// to the screen buffer.  This means that there only need
	// be a buffer when there's at least one authenticated client.
	m_encodemgr.SetBuffer(buffer);
}

void
vncClient::TriggerUpdateThread()
{
	// ALWAYS lock the client UpdateLock before calling this!

  // Check that this client has an update thread
	// The update thread never dissappears, and this is the only
	// thread allowed to create it, so this can be done without locking.

	if (!m_updatethread)
	{
		m_updatethread = new vncClientUpdateThread;
		if (!m_updatethread || 
      !m_updatethread->Init(this)) {
      Kill();
    }
	}				
  if (m_updatethread)
    m_updatethread->Trigger();
}

void
vncClient::UpdateMouse()
{
	// Flag that the mouse has moved
	omni_mutex_lock l(GetUpdateLock());
	m_mousemoved=TRUE;
}

void
vncClient::UpdateClipText(const char* text)
{
	omni_mutex_lock l(GetUpdateLock());
	if (m_clipboard_text) {
		free(m_clipboard_text);
		m_clipboard_text = 0;
	}
	m_clipboard_text = strdup(text);
  TriggerUpdateThread();
}

void
vncClient::UpdatePalette()
{
	omni_mutex_lock l(GetUpdateLock());
	m_palettechanged = TRUE;
}

void
vncClient::UpdateLocalFormat()
{
	DisableProtocol();
	//vnclog.Print(LL_INTERR, VNCLOG("updating local pixel format\n"));
	m_encodemgr.SetServerFormat();
	EnableProtocol();
}

// Functions used to set and retrieve the client settings
const char*
vncClient::GetClientName()
{
	return m_client_name;
}

// Enabling and disabling clipboard/GFX updates
void
vncClient::DisableProtocol()
{
	BOOL disable = FALSE;
	{	omni_mutex_lock l(GetUpdateLock());
		if (m_disable_protocol == 0)
			disable = TRUE;
		m_disable_protocol++;
		if (disable && m_updatethread)
			m_updatethread->EnableUpdates(FALSE);
	}
}

void
vncClient::EnableProtocol()
{
	{	omni_mutex_lock l(GetUpdateLock());
		if (m_disable_protocol == 0) {
			//vnclog.Print(LL_INTERR, VNCLOG("protocol enabled too many times!\n"));
			m_socket->Close();
			return;
		}
		m_disable_protocol--;
		if ((m_disable_protocol == 0) && m_updatethread)
			m_updatethread->EnableUpdates(TRUE);
	}
}

// Internal methods
BOOL
vncClient::SendRFBMsg(CARD8 type, BYTE *buffer, int buflen)
{
	// Set the message type
	((rfbServerToClientMsg *)buffer)->type = type;

	// Send the message
	if (!m_socket->SendExact((char *) buffer, buflen))
	{
		//vnclog.Print(LL_CONNERR, VNCLOG("failed to send RFB message to client\n"));

		Kill();
		return FALSE;
	}
	return TRUE;
}

BOOL
vncClient::SendUpdate(rfb::SimpleUpdateTracker &update)
{
	// If there is nothing to send then exit
  if (update.is_empty()) {
    //vnclog.Print(LL_INTERR, "no data to send\n");
		return FALSE;
  }

	// Get the update info from the tracker
	rfb::UpdateInfo update_info;
	update.get_update(update_info);
	update.clear();

	// Find out how many rectangles in total will be updated
	// This includes copyrects and changed rectangles split
	// up by codings such as CoRRE.

	int updates = 0;
	updates += update_info.copied.size();
	rfb::RectVector::const_iterator i;
	for (i=update_info.changed.begin(); i != update_info.changed.end(); i++) {
		updates += m_encodemgr.GetNumCodedRects(*i);
	}

	// If there are no updates then return
  if (updates == 0) {
    //vnclog.Print(LL_INTERR, "no data to send2\n");
    return FALSE;
  }

	// Otherwise, send <number of rectangles> header
	rfbFramebufferUpdateMsg header;
	header.nRects = Swap16IfLE(updates);
	if (!SendRFBMsg(rfbFramebufferUpdate, (BYTE *) &header, sz_rfbFramebufferUpdateMsg))
		return FALSE;

	// Send the copyrect rectangles
	if (!update_info.copied.empty()) {
		rfb::Point to_src_delta = update_info.copy_delta.negate();
		for (i=update_info.copied.begin(); i!=update_info.copied.end(); i++) {
			rfb::Point src = (*i).tl.translate(to_src_delta);
			if (!SendCopyRect(*i, src))
				return FALSE;
		}
	}

	// Encode & send the actual rectangles
  if (!SendRectangles(update_info.changed))
		return FALSE;

	return TRUE;
}

// Send a set of rectangles
BOOL
vncClient::SendRectangles(const rfb::RectVector &rects)
{
	rfb::Rect rect;
	rfb::RectVector::const_iterator i;

	// Work through the list of rectangles, sending each one
	for (i=rects.begin();i!=rects.end();i++) {
		if (!SendRectangle(*i))
			return FALSE;
	}

	return TRUE;
}

// Tell the encoder to send a single rectangle
BOOL
vncClient::SendRectangle(const rfb::Rect &rect)
{
	// Get the buffer to encode the rectangle
	UINT bytes = m_encodemgr.EncodeRect(rect);

	// If the data could not be encoded then bytes is zero
  if (bytes == 0) return FALSE;

  // Send the encoded data
	return m_socket->SendExact((char *)(m_encodemgr.GetClientBuffer()), bytes);
}

// Send a single CopyRect message
BOOL
vncClient::SendCopyRect(const rfb::Rect &dest, const rfb::Point &source)
{
	// Create the message header
	rfbFramebufferUpdateRectHeader copyrecthdr;
	copyrecthdr.r.x = Swap16IfLE(dest.tl.x);
	copyrecthdr.r.y = Swap16IfLE(dest.tl.y);
	copyrecthdr.r.w = Swap16IfLE(dest.br.x-dest.tl.x);
	copyrecthdr.r.h = Swap16IfLE(dest.br.y-dest.tl.y);
	copyrecthdr.encoding = Swap32IfLE(rfbEncodingCopyRect);

	// Create the CopyRect-specific section
	rfbCopyRect copyrectbody;
	copyrectbody.srcX = Swap16IfLE(source.x);
	copyrectbody.srcY = Swap16IfLE(source.y);

	// Now send the message;
	if (!m_socket->SendExact((char *)&copyrecthdr, sizeof(copyrecthdr)))
		return FALSE;
	if (!m_socket->SendExact((char *)&copyrectbody, sizeof(copyrectbody)))
		return FALSE;

	return TRUE;
}

// Send the encoder-generated palette to the client
// This function only returns FALSE if the SendExact fails - any other
// error is coped with internally...
BOOL
vncClient::SendPalette()
{
	rfbSetColourMapEntriesMsg setcmap;
	RGBQUAD *rgbquad;
	UINT ncolours = 256;

	// Reserve space for the colour data
	rgbquad = new RGBQUAD[ncolours];
	if (rgbquad == NULL)
		return TRUE;
					
	// Get the data
	if (!m_encodemgr.GetPalette(rgbquad, ncolours))
	{
		delete [] rgbquad;
		return TRUE;
	}

	// Compose the message
	setcmap.type = rfbSetColourMapEntries;
	setcmap.firstColour = Swap16IfLE(0);
	setcmap.nColours = Swap16IfLE(ncolours);

	if (!m_socket->SendExact((char *) &setcmap, sz_rfbSetColourMapEntriesMsg))
	{
		delete [] rgbquad;
		return FALSE;
	}

	// Now send the actual colour data...
	for (int i=0; i<ncolours; i++)
	{
		struct _PIXELDATA {
			CARD16 r, g, b;
		} pixeldata;

		pixeldata.r = Swap16IfLE(((CARD16)rgbquad[i].rgbRed) << 8);
		pixeldata.g = Swap16IfLE(((CARD16)rgbquad[i].rgbGreen) << 8);
		pixeldata.b = Swap16IfLE(((CARD16)rgbquad[i].rgbBlue) << 8);

		if (!m_socket->SendExact((char *) &pixeldata, sizeof(pixeldata)))
		{
			delete [] rgbquad;
			return FALSE;
		}
	}

	// Delete the rgbquad data
	delete [] rgbquad;

	return TRUE;
}

