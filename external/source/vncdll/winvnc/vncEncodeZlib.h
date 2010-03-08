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


// vncEncodeZlib object

// The vncEncodeZlib object uses a zlib based compression encoding to send rectangles
// to a client

class vncEncodeZlib;

#if !defined(_WINVNC_ENCODEZLIB)
#define _WINVNC_ENCODEZLIB
#pragma once

#include "vncEncoder.h"

#include "zlib/zlib.h"

// Minimum zlib rectangle size in bytes.  Anything smaller will
// not compress well due to overhead.
#define VNC_ENCODE_ZLIB_MIN_COMP_SIZE (17)

// Set maximum zlib rectangle size in pixels.  Always allow at least
// two scan lines.
#define ZLIB_MAX_RECT_SIZE (8*1024)
#define ZLIB_MAX_SIZE(min) ((( min * 2 ) > ZLIB_MAX_RECT_SIZE ) ? ( min * 2 ) : ZLIB_MAX_RECT_SIZE )


// Class definition

class vncEncodeZlib : public vncEncoder
{
// Fields
public:

// Methods
public:
	// Create/Destroy methods
	vncEncodeZlib();
	~vncEncodeZlib();

	virtual void Init();
	virtual const char* GetEncodingName() { return "Zlib"; }

	virtual UINT RequiredBuffSize(UINT width, UINT height);
	virtual UINT NumCodedRects(RECT &rect);

	virtual UINT EncodeRect(BYTE *source, VSocket *outConn, BYTE *dest, const RECT &rect, int offx, int offy);
	virtual UINT EncodeOneRect(BYTE *source, BYTE *dest, const RECT &rect);

// Implementation
protected:
	BYTE		      *m_buffer;
	int			       m_bufflen;
	struct z_stream_s  compStream;
	bool               compStreamInited;
	int offsetx;
	int offsety;
};

#endif // _WINVNC_ENCODEZLIB

