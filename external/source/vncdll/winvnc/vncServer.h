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
//#include "vncHTTPConnect.h"
#include "vncClient.h"
#include "vncRegion.h"
#include "vncPasswd.h"

// Includes
#include "stdhdrs.h"
#include "common.h"
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
	virtual void DisableClients(BOOL state);
	virtual BOOL ClientsDisabled();
	virtual vncClientId AddClient( AGENT_CTX * lpAgentContext );

	virtual BOOL Authenticated(vncClientId client);
	virtual void KillClient(vncClientId client);

	virtual size_t AuthClientCount();
	virtual size_t UnauthClientCount();

	virtual void KillAuthClients();
	virtual void WaitUntilAuthEmpty();

	virtual void KillUnauthClients();
	virtual void WaitUntilUnauthEmpty();

	// Has at least one client had a remote event?
	virtual BOOL RemoteEventReceived();

	// Client info retrieval/setup
	virtual vncClient* GetClient(vncClientId clientid);
	virtual vncClientList ClientList();

	virtual void BlockRemoteInput(BOOL block);

	virtual const char* GetClientName(vncClientId client);

	// Let a client remove itself
	virtual void RemoveClient(vncClientId client);

	// Connect/disconnect notification
	virtual BOOL AddNotify(HWND hwnd);
	virtual BOOL RemNotify(HWND hwnd);

	// Check mirror driver status
	virtual BOOL DesktopActive() { return m_desktop != NULL; }
	virtual BOOL DriverActive();

	virtual BOOL SetShareMonitorFromPoint(POINT pt);

protected:
	// Send a notification message
	virtual void DoNotify(UINT message, WPARAM wparam, LPARAM lparam);

public:
	// Update handling, used by clients to signal the screen server
	virtual void RequestUpdate();

	// Update handling, used by the screen server
	virtual void TriggerUpdate();
	virtual void UpdateRect(RECT &rect);
	virtual void UpdateRegion(vncRegion &region);
	virtual void CopyRect(RECT &dest, POINT &source);
	virtual void UpdateMouse();
	virtual void UpdateClipText(LPSTR text);
	virtual void UpdatePalette();

	// Polling mode handling
	virtual void PollUnderCursor(BOOL enable) {m_poll_undercursor = enable;};
	virtual BOOL PollUnderCursor() {return m_poll_undercursor;};
	virtual void PollForeground(BOOL enable) {m_poll_foreground = enable;};
	virtual BOOL PollForeground() {return m_poll_foreground;};
	virtual void PollFullScreen(BOOL enable) {m_poll_fullscreen = enable;};
	virtual BOOL PollFullScreen() {return m_poll_fullscreen;};
	virtual void DontSetHooks(BOOL enable);
	virtual BOOL DontSetHooks() {return m_dont_set_hooks;};
	virtual void DontUseDriver(BOOL enable);
	virtual BOOL DontUseDriver() {return m_dont_use_driver;};
	virtual void DriverDirectAccess(BOOL enable);
	virtual BOOL DriverDirectAccess() {return m_driver_direct_access_en;};

	virtual void PollConsoleOnly(BOOL enable) {m_poll_consoleonly = enable;};
	virtual BOOL PollConsoleOnly() {return m_poll_consoleonly;};
	virtual void PollOnEventOnly(BOOL enable) {m_poll_oneventonly = enable;};
	virtual BOOL PollOnEventOnly() {return m_poll_oneventonly;};

	// Client manipulation of the clipboard
	virtual void UpdateLocalClipText(LPSTR text);

	// Name and port number handling
	virtual void SetName(const char * name);
	virtual void SetPorts(const UINT port_rfb, const UINT port_http);
	virtual UINT GetPort() { return m_port; };
	virtual UINT GetHttpPort() { return m_port_http; };
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
	// form, not the plaintext form.  The buffer passwd MUST be MAXPWLEN in size.
	// If the parameter `activate' is FALSE, then the password is considered
	// undefined. If `activate' is FALSE, the password data still may be copied.
	// The return value of `Get' functions matches the `activate' parameter.
	virtual void SetPassword(BOOL activate, const char *passwd);
	virtual BOOL GetPassword(char *passwd);
	virtual void SetPasswordViewOnly(BOOL activate, const char *passwd);
	virtual BOOL GetPasswordViewOnly(char *passwd);

	// Determine is at least one valid password is set so authentication is
	// possible. This function returns TRUE if at least one of the passwords
	// (primary or view-only) is set, AND at least one of the passwords is
	// not empty if empty passwords are disabled.
	virtual BOOL ValidPasswordsSet();

	// Version of ValidPasswordsSet() that does not use m_valid_passwords_set.
	virtual BOOL ValidPasswordsSet_nocache();

	// Determine if there are valid passwords (primary or view-only) AND all
	// valid passwords are empty. If this function returns TRUE, no password
	// authentication will be requested.
	virtual BOOL ValidPasswordsEmpty();

	// Version of ValidPasswordsEmpty() that does not use m_valid_passwords_empty.
	virtual BOOL ValidPasswordsEmpty_nocache();

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

	// Tray icon disposition
	virtual BOOL SetDisableTrayIcon(BOOL disableTrayIcon);
	virtual BOOL GetDisableTrayIcon();

	// CORBA connection handling
	virtual BOOL CORBAConnect(BOOL on);
	virtual BOOL CORBAConnected();
	virtual void GetScreenInfo(int &width, int &height, int &depth);

	// Allow connections without password authentication?
	virtual void SetAuthRequired(BOOL reqd) {ResetPasswordsValidityInfo(); m_passwd_required = reqd;}
	virtual BOOL AuthRequired() {return m_passwd_required;};

	// Beep on connect/disconnect?
	virtual void SetBeepConnect(BOOL beepConn) {m_beepConnect = beepConn;};
	virtual BOOL GetBeepConnect() {return m_beepConnect;};
	virtual void SetBeepDisconnect(BOOL beepDisconn) {m_beepDisconnect = beepDisconn;};
	virtual BOOL GetBeepDisconnect() {return m_beepDisconnect;};

	// Handling of per-client connection authorisation
	virtual void SetAuthHosts(const char *hostlist);
	virtual char *AuthHosts();
	enum AcceptQueryReject {aqrAccept, aqrQuery, aqrReject};
	virtual AcceptQueryReject VerifyHost(const char *hostname);
	virtual AcceptQueryReject AdjustVerification(AcceptQueryReject host);

	// Blacklisting of machines which fail connection attempts too often
	// Such machines will fail VerifyHost for a short period
	virtual void AddAuthHostsBlacklist(const char *machine);
	virtual void RemAuthHostsBlacklist(const char *machine);

	// Connection querying settings
	virtual void SetQuerySetting(const UINT setting) {m_querysetting = setting;};
	virtual UINT QuerySetting() {return m_querysetting;};
	virtual void SetQueryTimeout(const UINT setting) {m_querytimeout = setting;};
	virtual UINT QueryTimeout() {return m_querytimeout;};
	virtual void SetQueryAccept(const BOOL setting) {m_queryaccept = setting;};
	virtual BOOL QueryAccept() {return m_queryaccept;};
	virtual void SetQueryAllowNoPass(const BOOL setting) {m_queryallownopass = setting;};
	virtual BOOL QueryAllowNoPass() {return m_queryallownopass;};

	// Whether or not to allow incoming HTTP connections
	virtual BOOL SetHttpdEnabled(BOOL enable_httpd, BOOL enable_params);
	virtual BOOL HttpdEnabled() {return m_httpd_enabled;};
	virtual BOOL HttpdParamsEnabled() {return m_httpd_params_enabled;};

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

	virtual void SetBlankScreen(const BOOL enable) {m_blank_screen = enable;};
	virtual BOOL GetBlankScreen() {return m_blank_screen;};

	// Whether or not to allow file transfers
	virtual void EnableFileTransfers(const BOOL enable) {m_enable_file_transfers = enable;}
	virtual BOOL FileTransfersEnabled() {return m_enable_file_transfers;}

    // Patrial desktop sharing
    virtual void WindowShared(BOOL enable) { m_WindowShared = enable; }
    virtual BOOL WindowShared() { return m_WindowShared; }
    virtual void SetMatchSizeFields(int left, int top, int right, int bottom);
	virtual RECT GetScreenAreaRect() { return m_screenarea_rect; }
	virtual void SetWindowShared(HWND hWnd);
    virtual HWND GetWindowShared() { return m_hwndShared; }
	virtual RECT GetSharedRect () { return m_shared_rect; }
	virtual void SetSharedRect (RECT rect) { m_shared_rect = rect; }
	virtual BOOL FullScreen() { return m_full_screen; }
	virtual void FullScreen(BOOL enable) { m_full_screen = enable; }
	virtual BOOL ScreenAreaShared() { return m_screen_area; }
	virtual void ScreenAreaShared(BOOL enable) { m_screen_area = enable; }
	virtual BOOL PrimaryDisplayOnlyShared() { return m_primary_display_only_shared; }
	virtual void PrimaryDisplayOnlyShared(BOOL enable) { m_primary_display_only_shared = enable; }

	virtual void SetNewFBSize(BOOL sendnewfb);
	virtual BOOL FullRgnRequested();
	virtual BOOL IncrRgnRequested();
	virtual	void UpdateLocalFormat();
	                                                                                     
	// Blocking remote input
	virtual void LocalInputPriority(BOOL enable);
	virtual BOOL LocalInputPriority() { return m_local_input_priority; }
	virtual void SetKeyboardCounter(int count);
	virtual int KeyboardCounter() { return m_remote_keyboard; }
	virtual void SetMouseCounter(int count, POINT &cursor_pos, BOOL mousemove);
	virtual int MouseCounter() { return m_remote_mouse; }
	virtual UINT DisableTime() { return m_disable_time; }
	virtual void SetDisableTime(UINT disabletime) { m_disable_time = disabletime; }
	virtual UINT GetPollingCycle() { return m_polling_cycle; }
	virtual void SetPollingCycle(UINT msec);
	virtual BOOL PollingCycleChanged() { return m_polling_cycle_changed; }
	virtual void PollingCycleChanged(BOOL change) { m_polling_cycle_changed = change; }

  BOOL checkPointer(vncClient *pClient);

	virtual void ClearWallpaperWait() { m_wallpaper_wait = FALSE; }
	virtual BOOL WallpaperWait() { return m_wallpaper_wait; }

	// Internal stuffs
protected:
	// Connection servers
	vncSockConnect		*m_socketConn;
	vncCorbaConnect		*m_corbaConn;
	//vncHTTPConnect		*m_httpConn;

	// The desktop handler
	vncDesktop			*m_desktop;

	// General preferences
	UINT				m_port;
	UINT				m_port_http;
	RECT			    m_shared_rect;
	RECT			    m_screenarea_rect;
	BOOL				m_autoportselect;
	char				m_password[MAXPWLEN];
	BOOL				m_password_set;
	char				m_password_viewonly[MAXPWLEN];
	BOOL				m_password_viewonly_set;
	BOOL				m_passwd_required;
	BOOL				m_loopback_allowed;
	BOOL				m_httpd_enabled;
	BOOL				m_httpd_params_enabled;
	BOOL				m_loopbackOnly;
	BOOL				m_disableTrayIcon;
	char				*m_auth_hosts;
	BOOL				m_enable_remote_inputs;
	BOOL				m_disable_local_inputs;
	int					m_lock_on_exit;
	int					m_connect_pri;
	BOOL				m_beepConnect;
	BOOL				m_beepDisconnect;
	UINT				m_querysetting;
	UINT				m_querytimeout;
	BOOL				m_queryaccept;
	BOOL				m_queryallownopass;
	BOOL				m_clients_disabled;
	UINT				m_idle_timeout;
	UINT				m_disable_time;

	BOOL				m_remove_wallpaper;
	BOOL				m_blank_screen;
	BOOL				m_enable_file_transfers;

	// Polling preferences
	BOOL				m_poll_fullscreen;
	BOOL				m_poll_foreground;
	BOOL				m_poll_undercursor;

	BOOL				m_poll_oneventonly;
	BOOL				m_poll_consoleonly;

	BOOL				m_dont_set_hooks;
	BOOL				m_dont_use_driver;
	BOOL				m_driver_direct_access_en;
// NOTE that it only has a status of preference;
// the effective status of direct access option is
// vncVideoDriver::m_fDirectAccessInEffect

	// screen area sharing preferences                                                   
	BOOL				m_shared_oneapplionly;               
	HWND				m_hwndShared;  
	BOOL				m_WindowShared;                      
	BOOL				m_full_screen;                       
	BOOL				m_screen_area;                       
	BOOL				m_primary_display_only_shared;

	// local event priority stuff                                        
	BOOL				m_local_input_priority;                    
	INT					m_remote_mouse;              
	INT					m_remote_keyboard;           
	POINT				m_cursor_pos;

	UINT				m_polling_cycle;
	BOOL				m_polling_cycle_changed;

	// Make sure to remove wallpaper _before_ the first update
	BOOL				m_wallpaper_wait;

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

	// The value that would be returned by ValidPasswordsSet(). This variable has correct
	// authentic value only if m_valid_passwords_set_cached is true. Maintaining this variable
	// prevents from decoding passwords each time ValidPasswordsSet() is called.
	BOOL				m_valid_passwords_set;

	// This variable set to true means that the value of m_valid_passwords_set is authentic.
	BOOL				m_valid_passwords_set_cached;

	// The value that would be returned by ValidPasswordsEmpty(). This variable has correct
	// authentic value only if m_valid_passwords_empty_cached is true. Maintaining this variable
	// prevents from decoding passwords each time ValidPasswordsEmpty() is called.
	BOOL				m_valid_passwords_empty;

	// This variable set to true means that the value of m_valid_passwords_empty is authentic.
	BOOL				m_valid_passwords_empty_cached;

	// A short function to invalidate both m_valid_passwords_set and m_valid_passwords_empty.
	void inline ResetPasswordsValidityInfo() {
		m_valid_passwords_set_cached = m_valid_passwords_empty_cached = FALSE;
	}
};

BOOL IsWinNT();
BOOL IsWinVerOrHigher(ULONG mj, ULONG mn);

RECT GetScreenRect();

#endif
