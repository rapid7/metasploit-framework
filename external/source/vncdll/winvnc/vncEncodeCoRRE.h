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


// vncEncodeCoRRE object

// The vncEncodeCoRRE object uses a compression encoding to send rectangles
// to a client

class vncEncodeCoRRE;

#if !defined(_WINVNC_ENCODECORRRE)
#define _WINVNC_ENCODECORRE
#pragma once

#include "vncEncoder.h"

// Class definition

class vncEncodeCoRRE : public vncEncoder
{
// Fields
public:

// Methods
public:
	// Create/Destroy methods
	vncEncodeCoRRE();
	~vncEncodeCoRRE();

	virtual void Init();
	virtual const char* GetEncodingName() { return "CoRRE"; }

	virtual UINT RequiredBuffSize(UINT width, UINT height);
	virtual UINT NumCodedRects(RECT &rect);

	virtual UINT EncodeRect(BYTE *source, BYTE *dest, const RECT &rect, int offx, int offy);
	virtual void SetCoRREMax(BYTE width, BYTE height);
protected:
	virtual UINT InternalEncodeRect(BYTE *source, BYTE *dest, const RECT &rect);
	virtual UINT EncodeSmallRect(BYTE *source, BYTE *dest, const RECT &rect);

// Implementation
protected:
	BYTE		*m_buffer;
	size_t		m_bufflen;

	// Maximum height & width for CoRRE
	int			m_maxwidth;
	int			m_maxheight;

	// Last-update stats for CoRRE
	UINT		m_encodedbytes, m_rectbytes;
	UINT		m_lastencodedbytes, m_lastrectbytes;
	int			m_maxadjust;
	int			m_threshold;
	BOOL		m_statsready;
	int			offsetx;
	int			offsety;
};

#endif // _WINVNC_ENCODECORRE

