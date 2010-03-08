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


// vncEncodeZlibHex object

// The vncEncodeZlibHex object uses a compression encoding to send rectangles
// to a client.  As with the hextile encoding, all rectangles are broken down
// into a matrix of 16x16 (or smaller at bottom/right) tiles, which are 
// individually encoded with a subencoding mechanism.  This encoding addds
// the ability to apply zlib compression to the raw and other hextile
// subencodings.

class vncEncodeZlibHex;

#if !defined(_WINVNC_ENCODEZLIBHEX)
#define _WINVNC_ENCODEZLIBHEX
#pragma once

#include "vncEncoder.h"

#include "zlib/zlib.h"

// Minimum zlib rectangle size in bytes.  Anything smaller will
// not compress well due to overhead.
#define VNC_ENCODE_ZLIBHEX_MIN_COMP_SIZE (17)

// Flag used to mark our compressors as uninitialized.
#define ZLIBHEX_COMP_UNINITED (-1)

// Size of the smallest update portion sent independently across
// the network.  This encoder can transmit partial updates to
// improve latency issues with performance.
#define VNC_ENCODE_ZLIBHEX_MIN_DATAXFER (1400)

// Class definition

class vncEncodeZlibHex : public vncEncoder
{
// Fields
public:

// Methods
public:
	// Create/Destroy methods
	vncEncodeZlibHex();
	~vncEncodeZlibHex();

	void Init();
	virtual const char* GetEncodingName() { return "ZlibHex"; }

	virtual UINT RequiredBuffSize(UINT width, UINT height);
	virtual UINT NumCodedRects(RECT &rect);

	// virtual UINT EncodeRect(BYTE *source, BYTE *dest, const RECT &rect);
	virtual UINT EncodeRect(BYTE *source, VSocket *outConn, BYTE *dest, const RECT &rect, int offx, int offy);

protected:
	virtual UINT zlibCompress(BYTE *from_buf, BYTE *to_buf, UINT length, struct z_stream_s *compressor);

	virtual UINT EncodeHextiles8(BYTE *source, BYTE *dest,
		VSocket *outConn, int x, int y, int w, int h);
	virtual UINT EncodeHextiles16(BYTE *source, BYTE *dest,
		VSocket *outConn, int x, int y, int w, int h);
	virtual UINT EncodeHextiles32(BYTE *source, BYTE *dest,
		VSocket *outConn, int x, int y, int w, int h);

// Implementation
protected:
	BYTE				*m_buffer;
	int					m_bufflen;
	int					offsetx;
	int					offsety;
	struct z_stream_s  compStreamRaw;
	struct z_stream_s  compStreamEncoded;
};

#endif // _WINVNC_ENCODEHEXTILE

