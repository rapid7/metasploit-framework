//  Copyright (C) 2001 Constantin Kaplinsky. All Rights Reserved.
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

// vncBuffer object

// The vncBuffer object provides a client-local copy of the screen
// It can tell the client which bits have changed in a given region
// It uses the specified vncDesktop to read screen data from

class vncBuffer;

#if !defined(_WINVNC_VNCBUFFER)
#define _WINVNC_VNCBUFFER
#pragma once

// Includes

#include "vncDesktop.h"
#include "vncEncoder.h"
#include "vncRegion.h"
#include "RectList.h"

// Class definition

class vncBuffer
{
// Methods
public:
	// Create/Destroy methods
	vncBuffer(vncDesktop *desktop);
	~vncBuffer();

	// BUFFER INFO
	RECT GetSize();
	rfbPixelFormat GetLocalFormat();
	BYTE *GetClientBuffer();
	BOOL GetRemotePalette(RGBQUAD *quadbuff, UINT ncolours);

	// BUFFER MANIPULATION
	BOOL CheckBuffer();

	// SCREEN SCANNING
	UINT GetNumCodedRects(RECT &rect);

	// SCREEN CAPTURE
	RECT GrabMouse();
	BOOL SetClientFormat(rfbPixelFormat &format);

	// CONFIGURING ENCODER
	void SetCompressLevel(int level);
	void SetQualityLevel(int level);
	void EnableXCursor(BOOL enable);
	void EnableRichCursor(BOOL enable);
	void EnableLastRect(BOOL enable);
	BOOL IsLastRectEnabled() { return m_use_lastrect; }

	// ENCODING
	BOOL SetEncoding(CARD32 encoding);

// semantics changed: offset now is the shared area origin
// in screen coordinates
	UINT TranslateRect(const RECT &rect, VSocket *outConn, int shared_org_x, int shared_org_y);

	// SENDING CURSOR SHAPE UPDATES
	BOOL IsCursorUpdatePending();
	BOOL SendCursorShape(VSocket *outConn);
	BOOL SendEmptyCursorShape(VSocket *outConn);
	void UpdateLocalFormat();

// Implementation
protected:

	// Routine to verify the mainbuff handle hasn't changed
	//inline BOOL FastCheckMainbuffer();
	
	BYTE		*m_mainbuff;
	RECT		m_mainrect;
	UINT		m_mainsize;

	BYTE		*m_clientbuff;
	UINT		m_clientbuffsize;
	BOOL		m_clientfmtset;

	UINT		m_bytesPerRow;

	rfbServerInitMsg	m_scrinfo;
	rfbPixelFormat		m_clientformat;
	rfbTranslateFnType	m_transfunc;

	vncDesktop	   *m_desktop;
	vncEncoder	   *m_encoder;
	bool           zlib_encoder_in_use;
	vncEncoder     *m_hold_zlib_encoder;
	bool           tight_encoder_in_use;
	vncEncoder     *m_hold_tight_encoder;
	bool           zlibhex_encoder_in_use;
	vncEncoder     *m_hold_zlibhex_encoder;

	// These variables mirror similar variables from vncEncoder class.
	// They are necessary because vncEncoder instance may be created after
	// their values were set.
	int				m_compresslevel;
	int				m_qualitylevel;
	BOOL			m_use_xcursor;
	BOOL			m_use_richcursor;
	BOOL			m_use_lastrect;

	HCURSOR			m_hcursor;		// Used to track cursor shape changes
};

#endif // _WINVNC_VNCBUFFER
