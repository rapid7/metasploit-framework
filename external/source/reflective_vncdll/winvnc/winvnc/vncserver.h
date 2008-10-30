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


// vncServer.h

// vncServer class handles the following functions:
// - Allowing clients to be dynamically added and removed
// - Propagating updates from the local vncDesktop object
//   to all the connected clients
// - Propagating mouse movements and keyboard events from
//   clients to the local vncDesktop
// It also creates the vncSockConnect and vncCORBAConnect
// servers, which respectively allow connections via sockets
// and via the ORB interface

class vncServer;

#if (!defined(_WINVNC_VNCSERVER))
#define _WINVNC_VNCSERVER

// Custom
#include "vncCORBAConnect.h"
#include "vncSockConnect.h"
#include "vncHTTPConnect.h"
#include "vncClient.h"
#include "rfbRegion.h"
#include "vncPasswd.h"

// Includes
#include "stdhdrs.h"
#include <omnithread.h>
#include <list>

// Define a datatype to handle lists of windows we wish to notify
typedef std::list<HWND> vncNotifyList;

// Some important constants;
const int MAX_CLIENTS = 128;

// The vncServer class itself

class vncServer
{
public:
	// Constructor/destructor
	vncServer();
	~vncServer();

	// Client handling functions
	virtual vncClientId AddClient(VSocket *socket, BOOL auth, BOOL shared);
	virtual vncClientId AddClient(VSocket *socket,
		BOOL auth, BOOL shared, BOOL teleport, int capability,
		BOOL keysenabled, BOOL ptrenabled);
	virtual BOOL Authenticated(vncClientId client);
	virtual void KillClient(vncClientId client);

	virtual UINT AuthClientCount();
	virtual UINT UnauthClientCount();

	virtual void KillAuthClients();
	virtual void WaitUntilAuthEmpty();

	virtual void KillUnauthClients();
	virtual void WaitUntilUnauthEmpty();

	// Are any clients ready to send updates?
	virtual BOOL UpdateWanted();

	// Has at least one client had a remote event?
	virtual BOOL RemoteEventReceived();

	// Client info retrieval/setup
	virtual vncClient* GetClient(vncClientId clientid);
	virtual vncClientList ClientList();

	virtual void SetTeleport(vncClientId client, BOOL teleport);
	virtual void SetCapability(vncClientId client, int capability);
	virtual void SetKeyboardEnabled(vncClientId client, BOOL enabled);
	virtual void SetPointerEnabled(vncClientId client, BOOL enabled);

	virtual BOOL IsTeleport(vncClientId client);
	virtual int GetCapability(vncClientId client);
	virtual BOOL GetKeyboardEnabled(vncClientId client);
	virtual BOOL GetPointerEnabled(vncClientId client);
	virtual const char* GetClientName(vncClientId client);

	// Let a client remove itself
	virtual void RemoveClient(vncClientId client);

	// Connect/disconnect notification
	virtual BOOL AddNotify(HWND hwnd);
	virtual BOOL RemNotify(HWND hwnd);

protected:
	// Send a notification message
	virtual void DoNotify(UINT message, WPARAM wparam, LPARAM lparam);

public:
	// Update handling, used by the screen server
	virtual rfb::UpdateTracker &GetUpdateTracker() {return m_update_tracker;};
	virtual void UpdateMouse();
	virtual void UpdateClipText(const char* text);
	virtual void UpdatePalette();
	virtual void UpdateLocalFormat();

	// Polling mode handling
	virtual void PollUnderCursor(BOOL enable) {m_poll_undercursor = enable;};
	virtual BOOL PollUnderCursor() {return m_poll_undercursor;};
	virtual void PollForeground(BOOL enable) {m_poll_foreground = enable;};
	virtual BOOL PollForeground() {return m_poll_foreground;};
	virtual void PollFullScreen(BOOL enable) {m_poll_fullscreen = enable;};
	virtual BOOL PollFullScreen() {return m_poll_fullscreen;};

	virtual void PollConsoleOnly(BOOL enable) {m_poll_consoleonly = enable;};
	virtual BOOL PollConsoleOnly() {return m_poll_consoleonly;};
	virtual void PollOnEventOnly(BOOL enable) {m_poll_oneventonly = enable;};
	virtual BOOL PollOnEventOnly() {return m_poll_oneventonly;};

	// Client manipulation of the clipboard
	virtual void UpdateLocalClipText(LPSTR text);

	// Name and port number handling
	virtual void SetName(const char * name);
	virtual void SetPort(const UINT port);
	virtual UINT GetPort();
	virtual void SetAutoPortSelect(const BOOL autoport) {
	    if (autoport && !m_autoportselect)
	    {
		BOOL sockconnect = SockConnected();
		SockConnect(FALSE);
		m_autoportselect = autoport;
		SockConnect(sockconnect);
	    }
		else
		{
			m_autoportselect = autoport;
		}
	};
	virtual BOOL AutoPortSelect() {return m_autoportselect;};

	// Password set/retrieve.  Note that these functions now handle the encrypted
	// form, not the plaintext form.  The buffer passwed MUST be MAXPWLEN in size.
	virtual void SetPassword(const char *passwd);
	virtual void GetPassword(char *passwd);

	// Remote input handling
	virtual void EnableRemoteInputs(BOOL enable);
	virtual BOOL RemoteInputsEnabled();

	// Local input handling
	virtual void DisableLocalInputs(BOOL disable);
	virtual BOOL LocalInputsDisabled();

	// General connection handling
	virtual void SetConnectPriority(UINT priority) {m_connect_pri = priority;};
	virtual UINT ConnectPriority() {return m_connect_pri;};

	// Socket connection handling
	virtual BOOL SockConnect(BOOL on);
	virtual BOOL SockConnected();
	virtual BOOL SetLoopbackOnly(BOOL loopbackOnly);
	virtual BOOL LoopbackOnly();

	// HTTP daemon handling
	virtual BOOL EnableHTTPConnect(BOOL enable);
	virtual BOOL HTTPConnectEnabled() {return m_enableHttpConn;};

	// CORBA connection handling
	virtual BOOL CORBAConnect(BOOL on);
	virtual BOOL CORBAConnected();
	virtual void GetScreenInfo(int &width, int &height, int &depth);

	// Allow connections if no password is set?
	virtual void SetAuthRequired(BOOL reqd) {m_passwd_required = reqd;};
	virtual BOOL AuthRequired() {return m_passwd_required;};

	// Handling of per-client connection authorisation
	virtual void SetAuthHosts(const char *hostlist);
	virtual char *AuthHosts();
	enum AcceptQueryReject {aqrAccept, aqrQuery, aqrReject};
	virtual AcceptQueryReject VerifyHost(const char *hostname);

	// Blacklisting of machines which fail connection attempts too often
	// Such machines will fail VerifyHost for a short period
	virtual void AddAuthHostsBlacklist(const char *machine);
	virtual void RemAuthHostsBlacklist(const char *machine);

	// Connection querying settings
	virtual void SetQuerySetting(const UINT setting) {m_querysetting = setting;};
	virtual UINT QuerySetting() {return m_querysetting;};
	virtual void SetQueryTimeout(const UINT setting) {m_querytimeout = setting;};
	virtual UINT QueryTimeout() {return m_querytimeout;};

	// Whether or not to allow connections from the local machine
	virtual void SetLoopbackOk(BOOL ok) {m_loopback_allowed = ok;};
	virtual BOOL LoopbackOk() {return m_loopback_allowed;};

	// Whether or not to shutdown or logoff when the last client leaves
	virtual void SetLockSettings(int ok) {m_lock_on_exit = ok;};
	virtual int LockSettings() {return m_lock_on_exit;};

	// Timeout for automatic disconnection of idle connections
	virtual void SetAutoIdleDisconnectTimeout(const UINT timeout) {m_idle_timeout = timeout;};
	virtual UINT AutoIdleDisconnectTimeout() {return m_idle_timeout;};

	// Removal of desktop wallpaper, etc
	virtual void EnableRemoveWallpaper(const BOOL enable) {m_remove_wallpaper = enable;};
	virtual BOOL RemoveWallpaperEnabled() {return m_remove_wallpaper;};

protected:
	// The vncServer UpdateTracker class
	// Behaves like a standard UpdateTracker, but propagates update
	// information to active clients' trackers

	class ServerUpdateTracker : public rfb::UpdateTracker {
	public:
		ServerUpdateTracker() : m_server(0) {};

		virtual void init(vncServer *server) {m_server=server;};

		virtual void add_changed(const rfb::Region2D &region);
		virtual void add_copied(const rfb::Region2D &dest, const rfb::Point &delta);
	protected:
		vncServer *m_server;
	};

	friend class ServerUpdateTracker;

	ServerUpdateTracker	m_update_tracker;

	// Internal stuffs
protected:
	// Connection servers
	vncSockConnect		*m_socketConn;
	vncCorbaConnect		*m_corbaConn;
	vncHTTPConnect		*m_httpConn;
	BOOL				m_enableHttpConn;

	// The desktop handler
	vncDesktop			*m_desktop;

	// General preferences
	UINT				m_port;
	BOOL				m_autoportselect;
	char				m_password[MAXPWLEN];
	BOOL				m_passwd_required;
	BOOL				m_loopback_allowed;
	BOOL				m_loopbackOnly;
	char				*m_auth_hosts;
	BOOL				m_enable_remote_inputs;
	BOOL				m_disable_local_inputs;
	int					m_lock_on_exit;
	int					m_connect_pri;
	UINT				m_querysetting;
	UINT				m_querytimeout;
	UINT				m_idle_timeout;

	BOOL				m_remove_wallpaper;

	// Polling preferences
	BOOL				m_poll_fullscreen;
	BOOL				m_poll_foreground;
	BOOL				m_poll_undercursor;

	BOOL				m_poll_oneventonly;
	BOOL				m_poll_consoleonly;

	// Name of this desktop
	char				*m_name;

	// Blacklist structures
	struct BlacklistEntry {
		BlacklistEntry *_next;
		char *_machineName;
		LARGE_INTEGER _lastRefTime;
		UINT _failureCount;
		BOOL _blocked;
	};
	BlacklistEntry		*m_blacklist;
	
	// The client lists - list of clients being authorised and ones
	// already authorised
	vncClientList		m_unauthClients;
	vncClientList		m_authClients;
	vncClient			*m_clientmap[MAX_CLIENTS];
	vncClientId			m_nextid;

	// Lock to protect the client list from concurrency - lock when reading/updating client list
	omni_mutex			m_clientsLock;
	// Lock to protect the desktop object from concurrency - lock when updating client list
	omni_mutex			m_desktopLock;

	// Signal set when a client removes itself
	omni_condition		*m_clientquitsig;

	// Set of windows to send notifications to
	vncNotifyList		m_notifyList;
};

#endif
