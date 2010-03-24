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


// ScrBuffer implementation

#include "stdhdrs.h"

// Header

#include "vncDesktop.h"
#include "vncEncoder.h"
#include "vncEncodeRRE.h"
#include "vncEncodeCoRRE.h"
#include "vncEncodeHexT.h"
#include "vncEncodeZlib.h"
#include "vncEncodeTight.h"
#include "vncEncodeZlibHex.h"
#include "MinMax.h"

#include "vncBuffer.h"

// Implementation

vncBuffer::vncBuffer(vncDesktop *desktop)
{
	m_desktop = desktop;
	m_encoder = NULL;
	zlib_encoder_in_use = false;
	m_hold_zlib_encoder = NULL;
	tight_encoder_in_use = false;
	m_hold_tight_encoder = NULL;
	zlibhex_encoder_in_use = false;
	m_hold_zlibhex_encoder = NULL;

	m_compresslevel = 6;
	m_qualitylevel = -1;
	m_use_xcursor = FALSE;
	m_use_richcursor = FALSE;
	m_use_lastrect = FALSE;

	m_hcursor = NULL;

	m_mainbuff = NULL;
	m_mainsize = 0;
	
	m_clientbuff = NULL;
	m_clientbuffsize = 0;
	m_clientfmtset = FALSE;

	// Initialise the screen buffers
	CheckBuffer();
}

vncBuffer::~vncBuffer()
{


	if (m_hold_zlib_encoder != NULL && m_hold_zlib_encoder != m_encoder) {
		m_hold_zlib_encoder->LogStats();
		delete m_hold_zlib_encoder;
		m_hold_zlib_encoder = NULL;
	}
	if (m_hold_tight_encoder != NULL && m_hold_tight_encoder != m_encoder) {
		m_hold_tight_encoder->LogStats();
		delete m_hold_tight_encoder;
		m_hold_tight_encoder = NULL;
	}
	if (m_hold_zlibhex_encoder != NULL && m_hold_zlibhex_encoder != m_encoder) {
		m_hold_zlibhex_encoder->LogStats();
		delete m_hold_zlibhex_encoder;
		m_hold_zlibhex_encoder = NULL;
	}
	if (m_encoder != NULL) {
		m_encoder->LogStats();
		delete m_encoder;
		m_encoder = NULL;
		m_hold_zlib_encoder = NULL;
		m_hold_tight_encoder = NULL;
		m_hold_zlibhex_encoder = NULL;
	}
	if (m_clientbuff != NULL) {
		delete m_clientbuff;
		m_clientbuff = NULL;
	}
	m_clientbuffsize = 0;
	m_mainsize = 0;
}

RECT
vncBuffer::GetSize()
{
	RECT rect;

	rect.left = 0;
	rect.top = 0;
	rect.right = m_scrinfo.framebufferWidth;
	rect.bottom = m_scrinfo.framebufferHeight;

	return rect;
}

rfbPixelFormat
vncBuffer::GetLocalFormat()
{
	return m_scrinfo.format;
}

BYTE *
vncBuffer::GetClientBuffer()
{
	return m_clientbuff;
}

BOOL
vncBuffer::GetRemotePalette(RGBQUAD *quadlist, UINT ncolours)
{
	// Try to get the RGBQUAD data from the encoder
	// This will only work if the remote client is palette-based,
	// in which case the encoder will be storing RGBQUAD data
	if (m_encoder == NULL)
	{
		return FALSE;
	}

	// Now get the palette data
	return m_encoder->GetRemotePalette(quadlist, ncolours);
}

BOOL
vncBuffer::CheckBuffer()
{
	// Get the screen format, in case it has changed
	m_desktop->FillDisplayInfo(&m_scrinfo);

	// If the client has not specified a pixel format then set one for it
	if (!m_clientfmtset) {
	    m_clientfmtset = TRUE;
	    m_clientformat = m_scrinfo.format;
	}

	// If the client has not selected an encoding then set one for it
	if (m_encoder == NULL) {
	    if (!SetEncoding(rfbEncodingRaw))
		return FALSE;
	}

	m_bytesPerRow = m_scrinfo.framebufferWidth * m_scrinfo.format.bitsPerPixel/8;

	// Check the client buffer is sufficient
	const UINT clientbuffsize =
	    m_encoder->RequiredBuffSize(m_scrinfo.framebufferWidth,
					m_scrinfo.framebufferHeight);
	if (m_clientbuffsize != clientbuffsize)
	{
	    if (m_clientbuff != NULL)
	    {
		delete [] m_clientbuff;
		m_clientbuff = NULL;
	    }
	    m_clientbuffsize = 0;

	    m_clientbuff = new BYTE [clientbuffsize];
	    if (m_clientbuff == NULL)
	    {		
		return FALSE;
	    }

	    m_clientbuffsize = clientbuffsize;

	    ZeroMemory(m_clientbuff, m_clientbuffsize);
	}

	// Take the main buffer pointer and size from vncDesktop 
	m_mainbuff = m_desktop->MainBuffer();
	m_mainrect = m_desktop->MainBufferRect();
	m_mainsize = m_desktop->ScreenBuffSize();
		
	return TRUE;
}




UINT
vncBuffer::GetNumCodedRects(RECT &rect)
{
	// Ask the encoder how many rectangles this update would become
	return m_encoder->NumCodedRects(rect);
}

RECT vncBuffer::GrabMouse()
{
// capture uncovered area
	m_desktop->CaptureScreen(m_desktop->MouseRect(), m_mainbuff);
// capture new mouse area
	m_desktop->CaptureMouse(m_mainbuff, m_mainsize);

	return m_desktop->MouseRect();
}

BOOL
vncBuffer::SetClientFormat(rfbPixelFormat &format)
{
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
/*
VOID vncBuffer::UpdateZLibDictionary( AGENT_CTX * lpAgentContext )
{
	do
	{
		if( !lpAgentContext || !m_encoder )
			break;

		dprintf( "UpdateZLibDictionary, updating the ZLib dictionaries..." );
		m_encoder->UpdateZLibDictionary( lpAgentContext );
		dprintf( "UpdateZLibDictionary, Finished updating the ZLib dictionaries." );

	} while( 0 );
}

VOID vncBuffer::DumpZLibDictionary( AGENT_CTX * lpAgentContext )
{
	do
	{
		if( !lpAgentContext || !m_encoder )
			break;

		m_encoder->DumpZLibDictionary( lpAgentContext );

	} while( 0 );
}
*/

BOOL vncBuffer::SetEncoding(CARD32 encoding)
{

	//m_desktop->FillDisplayInfo(&m_scrinfo);

	// Delete the old encoder
	if (m_encoder != NULL)
	{
		// If a Zlib-like encoders were in use, save corresponding object
		// (with dictionaries) for possible later use on this connection.
		if ( zlib_encoder_in_use )
		{
			m_hold_zlib_encoder = m_encoder;
		}
		else if ( tight_encoder_in_use )
		{
			m_hold_tight_encoder = m_encoder;
		}
		else if ( zlibhex_encoder_in_use )
		{
			m_hold_zlibhex_encoder = m_encoder;
		}
		else
		{
			m_encoder->LogStats();
			delete m_encoder;
		}
		m_encoder = NULL;
	}

	// Expect to not use the zlib encoder below.  However, this
	// is overriden if zlib was selected.
	zlib_encoder_in_use = false;
	tight_encoder_in_use = false;
	zlibhex_encoder_in_use = false;

	// Returns FALSE if the desired encoding cannot be used
	switch(encoding)
	{

	case rfbEncodingRaw:

		// Create a RAW encoder
		m_encoder = new vncEncoder;
		if (m_encoder == NULL)
			return FALSE;
		break;

	case rfbEncodingRRE:

		// Create a RRE encoder
		m_encoder = new vncEncodeRRE;
		if (m_encoder == NULL)
			return FALSE;
		break;

	case rfbEncodingCoRRE:

		// Create a CoRRE encoder
		m_encoder = new vncEncodeCoRRE;
		if (m_encoder == NULL)
			return FALSE;
		break;

	case rfbEncodingHextile:

		// Create a Hextile encoder
		m_encoder = new vncEncodeHexT;
		if (m_encoder == NULL)
			return FALSE;
		break;

	case rfbEncodingZlib:
		// Create a Zlib encoder, if needed.
		// If a Zlib encoder was used previously, then reuse it here
		// to maintain zlib dictionary synchronization with the viewer.
		if ( m_hold_zlib_encoder == NULL )
		{
			m_encoder = new vncEncodeZlib;
		}
		else
		{
			m_encoder = m_hold_zlib_encoder;
		}
		if (m_encoder == NULL)
			return FALSE;
		zlib_encoder_in_use = true;
		break;

	case rfbEncodingTight:

		// Create a Tight encoder, if needed.
		// If a Tight encoder was used previously, then reuse it here
		// to maintain zlib dictionaries synchronization with the viewer.
		if ( m_hold_tight_encoder == NULL )
		{
			m_encoder = new vncEncodeTight;
		}
		else
		{
			m_encoder = m_hold_tight_encoder;
		}
		if (m_encoder == NULL)
			return FALSE;
		tight_encoder_in_use = true;
		break;

	case rfbEncodingZlibHex:

		// Create a ZlibHex encoder, if needed.
		// If a ZlibHex encoder was used previously, then reuse it here
		// to maintain zlib dictionary synchronization with the viewer.
		if ( m_hold_zlibhex_encoder == NULL )
		{
			m_encoder = new vncEncodeZlibHex;
		}
		else
		{
			m_encoder = m_hold_zlibhex_encoder;
		}
		if (m_encoder == NULL)
			return FALSE;
		zlibhex_encoder_in_use = true;
		break;

	default:
		// An unknown encoding was specified

		return FALSE;
	}

	// Initialise it and give it the pixel format
	m_encoder->Init();
	m_encoder->SetLocalFormat(
			m_scrinfo.format,
			m_scrinfo.framebufferWidth,
			m_scrinfo.framebufferHeight);

	// Duplicate our member fields in new Encoder.
	m_encoder->SetCompressLevel(m_compresslevel);
	m_encoder->SetQualityLevel(m_qualitylevel);
	m_encoder->EnableXCursor(m_use_xcursor);
	m_encoder->EnableRichCursor(m_use_richcursor);
	m_encoder->EnableLastRect(m_use_lastrect);

	if (m_clientfmtset)
		if (!m_encoder->SetRemoteFormat(m_clientformat))
		{
			return FALSE;
		}

	// Check that the client buffer is compatible
	return CheckBuffer();
}

void
vncBuffer::SetCompressLevel(int level)
{
	m_compresslevel = (level >= 0 && level <= 9) ? level : 6;
	if (m_encoder != NULL)
		m_encoder->SetCompressLevel(m_compresslevel);
}

void
vncBuffer::SetQualityLevel(int level)
{
	m_qualitylevel = (level >= 0 && level <= 9) ? level : -1;
	if (m_encoder != NULL)
		m_encoder->SetQualityLevel(m_qualitylevel);
}

void
vncBuffer::EnableXCursor(BOOL enable)
{
	m_use_xcursor = enable;
	if (m_encoder != NULL) {
		m_encoder->EnableXCursor(enable);
	}
	m_hcursor = NULL;
}

void
vncBuffer::EnableRichCursor(BOOL enable)
{
	m_use_richcursor = enable;
	if (m_encoder != NULL) {
		m_encoder->EnableRichCursor(enable);
	}
	m_hcursor = NULL;
}

void
vncBuffer::EnableLastRect(BOOL enable)
{
	m_use_lastrect = enable;
	if (m_encoder != NULL) {
		m_encoder->EnableLastRect(enable);
	}
}


// Routine to translate a rectangle between pixel formats
// semantics changed:
// offset now is the shared area origin in screen coordinates
UINT vncBuffer::TranslateRect(
		const RECT &rect,
		VSocket *outConn,
		int shared_org_x,
		int shared_org_y)
{
	// Call the encoder to encode the rectangle into the client buffer...

// Translate (==> EncodeRect also) assumes mainbuff-relative coordinates
// so we need to adjust the rect.
// also, presentation (fb) rect is required.
	RECT ar;
	ar.left = rect.left - m_mainrect.left;
	ar.top = rect.top -  m_mainrect.top;
	ar.right = rect.right - m_mainrect.left;
	ar.bottom = rect.bottom - m_mainrect.top;

	return m_encoder->EncodeRect(
		m_mainbuff,
		outConn,
		m_clientbuff,
		ar,
		shared_org_x - m_mainrect.left,
		shared_org_y - m_mainrect.top);
}

// Check if cursor shape update should be sent
BOOL
vncBuffer::IsCursorUpdatePending()
{
	if (m_use_xcursor || m_use_richcursor) {
		HCURSOR temp_hcursor = m_desktop->GetCursor();
		if (temp_hcursor != m_hcursor) {
			m_hcursor = temp_hcursor;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL
vncBuffer::SendCursorShape(VSocket *outConn) {
	return m_encoder->SendCursorShape(outConn, m_desktop);
}

BOOL
vncBuffer::SendEmptyCursorShape(VSocket *outConn) {
	return m_encoder->SendEmptyCursorShape(outConn);
}

void
vncBuffer::UpdateLocalFormat() {
	CheckBuffer();
	m_encoder->SetLocalFormat(
			m_scrinfo.format,
			m_scrinfo.framebufferWidth,
			m_scrinfo.framebufferHeight);
}
