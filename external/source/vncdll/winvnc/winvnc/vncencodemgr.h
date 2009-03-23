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

// vncEncodeMgr

// This class is used internally by vncClient to offload the handling of
// bitmap data encoding and translation.  Trying to avoid bloating the
// already rather bloaty vncClient class!

class vncEncodeMgr;

#if !defined(_WINVNC_VNCENCODEMGR)
#define _WINVNC_VNCENCODEMGR
#pragma once

// Includes

#include "vncEncoder.h"
#include "vncEncodeRRE.h"
#include "vncEncodeCoRRE.h"
#include "vncEncodeHexT.h"
#include "vncEncodeZRLE.h"
#include "vncBuffer.h"

#include <rdr/Exception.h>

//
// -=- Define the Encoding Manager interface
// 

class vncEncodeMgr
{
public:
	// Create/Destroy methods
	inline vncEncodeMgr();
	inline ~vncEncodeMgr();

	inline void SetBuffer(vncBuffer *buffer);

	// BUFFER INFO
	inline rfb::Rect GetSize() {return m_buffer->GetSize();};
	inline BYTE *GetClientBuffer();
	inline UINT GetClientBuffSize();
	inline BOOL GetPalette(RGBQUAD *quadbuff, UINT ncolours);

	inline omni_mutex& GetUpdateLock() {return m_buffer->m_desktop->GetUpdateLock();};

	// MIRRORING DISPLAY TO BACK-BUFFER
	inline void GrabRegion(const rfb::Region2D &src);

	// ENCODING & TRANSLATION
	inline UINT GetNumCodedRects(const rfb::Rect &rect);
	inline BOOL SetEncoding(CARD32 encoding);
	inline UINT EncodeRect(const rfb::Rect &rect);
	inline BOOL SetServerFormat();
	inline BOOL SetClientFormat(rfbPixelFormat &format);
	inline rfbPixelFormat GetClientFormat() {return m_clientformat;};

protected:

	// Routine used internally to ensure the client buffer is OK
	inline BOOL CheckBuffer();

	// Pixel buffers and access to display buffer
	BYTE		*m_clientbuff;
	UINT		m_clientbuffsize;
	BYTE		*m_clientbackbuff;
	UINT		m_clientbackbuffsize;

	// Pixel formats, translation and encoding
	rfbPixelFormat	m_clientformat;
	BOOL			m_clientfmtset;
	rfbServerInitMsg	m_scrinfo;
	rfbTranslateFnType	m_transfunc;
	vncEncoder	*m_encoder;
	vncEncoder* zrleEncoder;
public:
	vncBuffer	*m_buffer;
};

//
// -=- Constructor/destructor
//

inline vncEncodeMgr::vncEncodeMgr()
  : zrleEncoder(0)
{
	m_encoder = NULL;
	m_buffer=NULL;

	m_clientbuff = NULL;
	m_clientbuffsize = 0;
	m_clientbackbuff = NULL;
	m_clientbackbuffsize = 0;

	m_clientfmtset = FALSE;
}

inline vncEncodeMgr::~vncEncodeMgr()
{
	if (zrleEncoder && zrleEncoder != m_encoder)
		delete zrleEncoder;
	if (m_encoder != NULL)
	{
		delete m_encoder;
		m_encoder = NULL;
	}
	if (m_clientbuff != NULL)
	{
		delete m_clientbuff;
		m_clientbuff = NULL;
	}
	if (m_clientbackbuff != NULL)
	{
		delete m_clientbackbuff;
		m_clientbackbuff = NULL;
	}
}

inline void
vncEncodeMgr::SetBuffer(vncBuffer *buffer)
{
	m_buffer=buffer;
	CheckBuffer();
	GrabRegion(rfb::Region2D(0, 0,
		m_scrinfo.framebufferWidth,
		m_scrinfo.framebufferHeight));
}

//
// -=- Encoding of pixel data for transmission
//

inline BYTE *
vncEncodeMgr::GetClientBuffer()
{
	return m_clientbuff;
}

inline BOOL
vncEncodeMgr::GetPalette(RGBQUAD *quadlist, UINT ncolours)
{
	// Try to get the RGBQUAD data from the encoder
	// This will only work if the remote client is palette-based,
	// in which case the encoder will be storing RGBQUAD data
	if (m_encoder == NULL)
	{
		//vnclog.Print(LL_INTWARN, VNCLOG("GetPalette called but no encoder set\n"));
		return FALSE;
	}

	// Now get the palette data
	return m_encoder->GetRemotePalette(quadlist, ncolours);
}

inline BOOL
vncEncodeMgr::CheckBuffer()
{
	// Get the screen format, in case it has changed
	m_buffer->m_desktop->FillDisplayInfo(&m_scrinfo);

	// If the client has not specified a pixel format then set one for it
	if (!m_clientfmtset) {
	    m_clientfmtset = TRUE;
	    m_clientformat = m_scrinfo.format;
	}

	// If the client has not selected an encoding then set one for it
	if ((m_encoder == NULL) && (!SetEncoding(rfbEncodingRaw)))
		return FALSE;

	// Check the client buffer is sufficient
	const UINT clientbuffsize =
	    m_encoder->RequiredBuffSize(m_scrinfo.framebufferWidth,
									m_scrinfo.framebufferHeight);
	if (m_clientbuffsize != clientbuffsize)
	{
		//vnclog.Print(LL_INTINFO, VNCLOG("request client buffer[%u]\n"), clientbuffsize);
	    if (m_clientbuff != NULL)
	    {
			delete [] m_clientbuff;
			m_clientbuff = NULL;
	    }
	    m_clientbuffsize = 0;

	    m_clientbuff = new BYTE [clientbuffsize];
	    if (m_clientbuff == NULL)
	    {		
			//vnclog.Print(LL_INTERR, VNCLOG("unable to allocate client buffer[%u]\n"), clientbuffsize);
			return FALSE;
	    }
		memset(m_clientbuff, 0, clientbuffsize);
	    m_clientbuffsize = clientbuffsize;
	}

	// Check the client backing buffer matches the server back buffer
	const UINT backbuffsize = m_buffer->m_backbuffsize;
	if (m_clientbackbuffsize != backbuffsize)
	{
		//vnclog.Print(LL_INTINFO, VNCLOG("request client back buffer[%u]\n"), backbuffsize);
		if (m_clientbackbuff) {
			delete [] m_clientbackbuff;
			m_clientbackbuff = 0;
		}
		m_clientbackbuffsize = 0;

		m_clientbackbuff = new BYTE[backbuffsize];
		if (!m_clientbackbuff) {
			//vnclog.Print(LL_INTERR, VNCLOG("unable to allocate client back buffer[%u]\n"), backbuffsize);
			return FALSE;
		}
		memset(m_clientbackbuff, 0, backbuffsize);
		m_clientbackbuffsize = backbuffsize;
	}

	//vnclog.Print(LL_INTINFO, VNCLOG("remote buffer=%u\n"), m_clientbuffsize);

	return TRUE;
}

// Set the encoding to use
inline BOOL
vncEncodeMgr::SetEncoding(CARD32 encoding)
{
	// Delete the old encoder
	if (m_encoder != NULL)
	{
		if (m_encoder != zrleEncoder)
			delete m_encoder;
		m_encoder = NULL;
	}

	// Returns FALSE if the desired encoding cannot be used
	switch(encoding)
	{

	case rfbEncodingRaw:

		//vnclog.Print(LL_INTINFO, VNCLOG("raw encoder requested\n"));

		// Create a RAW encoder
		m_encoder = new vncEncoder;
		if (m_encoder == NULL)
			return FALSE;
		break;

	case rfbEncodingRRE:

		//vnclog.Print(LL_INTINFO, VNCLOG("RRE encoder requested\n"));

		// Create a RRE encoder
		m_encoder = new vncEncodeRRE;
		if (m_encoder == NULL)
			return FALSE;
		break;

	case rfbEncodingCoRRE:

		//vnclog.Print(LL_INTINFO, VNCLOG("CoRRE encoder requested\n"));

		// Create a CoRRE encoder
		m_encoder = new vncEncodeCoRRE;
		if (m_encoder == NULL)
			return FALSE;
		break;

	case rfbEncodingHextile:

		//vnclog.Print(LL_INTINFO, VNCLOG("Hextile encoder requested\n"));

		// Create a CoRRE encoder
		m_encoder = new vncEncodeHexT;
		if (m_encoder == NULL)
			return FALSE;
		break;

	case rfbEncodingZRLE:
		//vnclog.Print(LL_INTINFO, VNCLOG("ZRLE encoder requested\n"));
    if (!zrleEncoder) {
      try {
			  zrleEncoder = new vncEncodeZRLE;
      } catch (rdr::Exception& e) {
        //vnclog.Print(LL_INTERR, VNCLOG("ZRLE error:%s\n"), e.str());
      }
    }
		if (zrleEncoder)
      m_encoder = zrleEncoder;
		break;

	default:
		// An unknown encoding was specified
		//vnclog.Print(LL_INTERR, VNCLOG("unknown encoder requested\n"));

		return FALSE;
	}

	// Initialise it and give it the pixel format
	m_encoder->Init();
	m_encoder->SetLocalFormat(
			m_scrinfo.format,
			m_scrinfo.framebufferWidth,
			m_scrinfo.framebufferHeight);
	if (m_clientfmtset)
		if (!m_encoder->SetRemoteFormat(m_clientformat))
		{
			//vnclog.Print(LL_INTERR, VNCLOG("client pixel format is not supported\n"));

			return FALSE;
		}

	// Check that the client buffer is compatible
	return CheckBuffer();
}

// Predict how many update rectangles a given rect will encode to
// For Raw, RRE or Hextile, this is always 1.  For CoRRE, may be more,
// because each update rect is limited in size.
inline UINT
vncEncodeMgr::GetNumCodedRects(const rfb::Rect &rect)
{
	return m_encoder->NumCodedRects(rect);
}

//
// -=- Pixel format translation
//

// Update the local pixel format used by the encoder
inline BOOL
vncEncodeMgr::SetServerFormat()
{
	if (m_encoder) {
		CheckBuffer();
		return m_encoder->SetLocalFormat(
			m_scrinfo.format,
			m_scrinfo.framebufferWidth,
			m_scrinfo.framebufferHeight);
	}
	return FALSE;
}

// Specify the client's pixel format
inline BOOL
vncEncodeMgr::SetClientFormat(rfbPixelFormat &format)
{
	//vnclog.Print(LL_INTINFO, VNCLOG("SetClientFormat called\n"));
	
	// Save the desired format
	m_clientfmtset = TRUE;
	m_clientformat = format;

	// Tell the encoder of the new format
	if (m_encoder != NULL)
		m_encoder->SetRemoteFormat(format);

	// Check that the output buffer is sufficient
	if (!CheckBuffer())
		return FALSE;

	return TRUE;
}

// Copy a region from the server back-buffer to the client back-buffer,
// prior to encoding
inline void
vncEncodeMgr::GrabRegion(const rfb::Region2D &region) {
	rfb::RectVector rects;
	rfb::RectVector::const_iterator i;
	if (!region.get_rects(rects, 1, 1)) return;
	if (!m_clientbackbuff) {
		//vnclog.Print(LL_INTERR, "no client back-buffer available\n");
		return;
	}
	const UINT width = m_scrinfo.framebufferWidth;
	const UINT bytesPerPixel = m_scrinfo.format.bitsPerPixel/8;
	const UINT bytesPerRow = bytesPerPixel * width;
	for (i=rects.begin(); i!=rects.end(); i++) {
		rfb::Rect rect = *i;
		UINT rowstart = (bytesPerRow * rect.tl.y) + (bytesPerPixel * rect.tl.x);
		UINT rowlen = (bytesPerPixel * (rect.br.x-rect.tl.x));
		BYTE *src = &m_buffer->m_backbuff[rowstart];
		BYTE *dest = &m_clientbackbuff[rowstart];
		for (UINT y=rect.tl.y; y<rect.br.y; y++) {
			memcpy(dest, src, rowlen);
			src += bytesPerRow;
			dest += bytesPerRow;
		}
	}
}

// Translate a rectangle to the client's pixel format
inline UINT
vncEncodeMgr::EncodeRect(const rfb::Rect &rect)
{
	// Call the encoder to encode the rectangle into the client buffer...
	if (!m_clientbackbuff) {
		//vnclog.Print(LL_INTERR, "no client back-buffer available in EncodeRect\n");
		return 0;
	}
	return m_encoder->EncodeRect(m_clientbackbuff, m_clientbuff, rect);
}

#endif // _WINVNC_VNCENCODEMGR

