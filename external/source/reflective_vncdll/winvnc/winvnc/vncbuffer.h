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

// vncBuffer object

// The vncBuffer object provides a client-local copy of the screen
// It can tell the client which bits have changed in a given region
// It uses the specified vncDesktop to read screen data from

class vncBuffer;

#if !defined(_WINVNC_VNCBUFFER)
#define _WINVNC_VNCBUFFER
#pragma once

// Includes

#include "stdhdrs.h"
#include "vncEncoder.h"
#include "rfbRegion.h"
#include "rfbRect.h"
#include "rfb.h"

// Class definition

class vncDesktop;

class vncBuffer
{
// Methods
public:
	// Create/Destroy methods
	vncBuffer();
	~vncBuffer();

	void SetDesktop(vncDesktop *desktop);

	// BUFFER INFO
	rfb::Rect GetSize();
	rfbPixelFormat GetLocalFormat();

	// BUFFER MANIPULATION
	BOOL CheckBuffer();

	// SCREEN SCANNING
	void Clear(const rfb::Rect &rect);
	void CheckRegion(rfb::Region2D &dest, const rfb::Region2D &src);
	void CheckRect(rfb::Region2D &dest, const rfb::Rect &src);

	// SCREEN CAPTURE
	void CopyRect(const rfb::Rect &dest, const rfb::Point &delta);
	void GrabMouse();
	void GrabRegion(const rfb::Region2D &src);
	void GetMousePos(rfb::Rect &rect);

// Implementation
protected:

	// Routine to verify the mainbuff handle hasn't changed
	BOOL FastCheckMainbuffer();
	
	// Fetch pixel data to the main buffer from the screen
	void GrabRect(const rfb::Rect &rect);

	BYTE		*m_mainbuff;
	BOOL		m_freemainbuff;

	UINT		m_bytesPerRow;

	rfbServerInitMsg	m_scrinfo;

public:
	// vncEncodeMgr reads data from back buffer directly when encoding
	BYTE		*m_backbuff;
	UINT		m_backbuffsize;

	vncDesktop	*m_desktop;
};

#endif // _WINVNC_VNCBUFFER
