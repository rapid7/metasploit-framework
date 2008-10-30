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


// vncClient.h

// vncClient class handles the following functions:
// - Recieves requests from the connected client and
//   handles them
// - Handles incoming updates properly, using a vncBuffer
//   object to keep track of screen changes
// It uses a vncBuffer and is passed the vncDesktop and
// vncServer to communicate with.

class vncClient;
typedef SHORT vncClientId;

#if (!defined(_WINVNC_VNCCLIENT))
#define _WINVNC_VNCCLIENT

#include <list>

typedef std::list<vncClientId> vncClientList;

// Includes
#include "stdhdrs.h"
#include "VSocket.h"
#include <omnithread.h>

// Custom
#include "vncDesktop.h"
#include "rfbRegion.h"
#include "rfbUpdateTracker.h"
#include "vncBuffer.h"
#include "vncEncodeMgr.h"

// The vncClient class itself

class vncClient
{
public:
	// Constructor/destructor
	vncClient();
	~vncClient();

	// Allow the client thread to see inside the client object
	friend class vncClientThread;
	friend class vncClientUpdateThread;

	// Init
	virtual BOOL Init(vncServer *server,
						VSocket *socket,
						BOOL auth,
						BOOL shared,
						vncClientId newid);

	// Kill
	// The server uses this to close the client socket, causing the
	// client thread to fail, which in turn deletes the client object
	virtual void Kill();

	// Client manipulation functions for use by the server
	virtual void SetBuffer(vncBuffer *buffer);

	// Update handling functions
	// These all lock the UpdateLock themselves
	virtual void UpdateMouse();
	virtual void UpdateClipText(const char* text);
	virtual void UpdatePalette();
	virtual void UpdateLocalFormat();

	// Is the client waiting on an update?
	// YES IFF there is an incremental update region,
	//     AND no changed or copied updates intersect it
	virtual BOOL UpdateWanted() {
		omni_mutex_lock l(GetUpdateLock());
		return  !m_incr_rgn.is_empty() &&
			m_incr_rgn.intersect(m_update_tracker.get_changed_region()).is_empty() &&
			m_incr_rgn.intersect(m_update_tracker.get_copied_region()).is_empty();
	};

	// Has the client sent an input event?
	virtual BOOL RemoteEventReceived() {
		BOOL result = m_remoteevent;
		m_remoteevent = FALSE;
		return result;
	};

	// The UpdateLock
	// This must be held for a number of routines to be successfully invoked...
	virtual omni_mutex& GetUpdateLock() {return m_encodemgr.GetUpdateLock();};

	// Functions for setting & getting the client settings
	virtual void SetTeleport(BOOL teleport) {m_teleport = teleport;};
	virtual void EnableKeyboard(BOOL enable) {m_keyboardenabled = enable;};
	virtual void EnablePointer(BOOL enable) {m_pointerenabled = enable;};
	virtual void SetCapability(int capability) {m_capability = capability;};

	virtual BOOL IsTeleport() {return m_teleport;};
	virtual BOOL IsKeyboardEnabled() {return m_keyboardenabled;};
	virtual BOOL IsPointerEnabled() {return m_pointerenabled;};
	virtual int GetCapability() {return m_capability;};
	virtual const char *GetClientName();
	virtual vncClientId GetClientId() {return m_id;};

	// Disable/enable protocol messages to the client
	virtual void DisableProtocol();
	virtual void EnableProtocol();

	// Update routines
protected:
	BOOL SendUpdate(rfb::SimpleUpdateTracker &update);
	BOOL SendRFBMsg(CARD8 type, BYTE *buffer, int buflen);
	BOOL SendRectangles(const rfb::RectVector &rects);
	BOOL SendRectangle(const rfb::Rect &rect);
	BOOL SendCopyRect(const rfb::Rect &dest, const rfb::Point &source);
	BOOL SendPalette();

	void TriggerUpdateThread();

	void PollWindow(HWND hwnd);

	// Specialised client-side UpdateTracker
protected:

	// This update tracker stores updates it receives and
	// kicks the client update thread every time one is received

	class ClientUpdateTracker : public rfb::SimpleUpdateTracker {
	public:
		ClientUpdateTracker() : m_client(0) {};
		virtual ~ClientUpdateTracker() {};

		void init(vncClient *client) {m_client=client;}

    // XXX Always call with GetUpdateLock() held!
		virtual void add_changed(const rfb::Region2D &region) {
			SimpleUpdateTracker::add_changed(region);
			m_client->TriggerUpdateThread();
		}
		virtual void add_copied(const rfb::Region2D &dest, const rfb::Point &delta) {
			SimpleUpdateTracker::add_copied(dest, delta);
			m_client->TriggerUpdateThread();
		}
		virtual void clear() {
			SimpleUpdateTracker::clear();
		}

		virtual void flush_update(rfb::UpdateInfo &info, const rfb::Region2D &cliprgn) {;
			SimpleUpdateTracker::flush_update(info, cliprgn);
		}
		virtual void flush_update(rfb::UpdateTracker &to, const rfb::Region2D &cliprgn) {;
			SimpleUpdateTracker::flush_update(to, cliprgn);
		}

		virtual void get_update(rfb::UpdateInfo &info) const {;
			SimpleUpdateTracker::get_update(info);
		}
		virtual void get_update(rfb::UpdateTracker &to) const {
			SimpleUpdateTracker::get_update(to);
		}

		virtual bool is_empty() {
			return SimpleUpdateTracker::is_empty();
		}
	protected:
		vncClient *m_client;
	};

	friend class ClientUpdateTracker;

	// Make the update tracker available externally
public:

	rfb::UpdateTracker &GetUpdateTracker() {return m_update_tracker;};

	// Internal stuffs
protected:
	// Per-client settings
	BOOL			m_teleport;
	BOOL			m_keyboardenabled;
	BOOL			m_pointerenabled;
	int				m_capability;
	vncClientId		m_id;

	// Pixel translation & encoding handler
	vncEncodeMgr	m_encodemgr;

	// The server
	vncServer		*m_server;

	// The socket
	VSocket			*m_socket;
	char			*m_client_name;

	// The client thread
	omni_thread		*m_thread;


	// Count to indicate whether updates, clipboards, etc can be sent
	// to the client.  If 0 then OK, otherwise not.
	ULONG			m_disable_protocol;

	// User input information
	rfb::Rect		m_oldmousepos;
	BOOL			m_mousemoved;
	rfbPointerEventMsg	m_ptrevent;

	// Update tracking structures
	ClientUpdateTracker	m_update_tracker;

	// Client update transmission thread
	vncClientUpdateThread *m_updatethread;

	// Requested update region & requested flag
	rfb::Region2D	m_incr_rgn;

	// Full screen rectangle
	rfb::Rect		m_fullscreen;

	// When the local display is palettized, it sometimes changes...
	BOOL			m_palettechanged;

	// Information used in polling mode!
	BOOL			m_remoteevent;

	// Clipboard data
	char*			m_clipboard_text;
};

#endif
