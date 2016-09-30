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


// vncEncodeZlib

// This file implements the vncEncoder-derived vncEncodeZlib class.
// This class overrides some vncEncoder functions to produce a bitmap
// to Zlib encoder.  Zlib is much more efficient than RAW format on
// most screen data and usually twice as efficient as hextile.  Of
// course, zlib compression uses more CPU time on the server.
// However, over slower (64kbps or less) connections, the reduction
// in data transmitted usually outweighs the extra latency added
// while the server CPU performs the compression algorithms.

#include "vncEncodeZlib.h"

vncEncodeZlib::vncEncodeZlib()
{
	m_buffer = NULL;
	m_bufflen = 0;
	compStreamInited = false;
}

vncEncodeZlib::~vncEncodeZlib()
{
	if (m_buffer != NULL)
	{
		delete [] m_buffer;
		m_buffer = NULL;
	}
	if ( compStreamInited == true )
	{
		deflateEnd( &compStream );
	}
	compStreamInited = false;
}

void
vncEncodeZlib::Init()
{
	vncEncoder::Init();
}

UINT
vncEncodeZlib::RequiredBuffSize(UINT width, UINT height)
{
	int result;

	// The zlib library specifies a maximum compressed size of
	// the raw size plus one percent plus 8 bytes.  We also need
	// to cover the zlib header space.
	result = vncEncoder::RequiredBuffSize(width, height);
	result += ((result / 100) + 8) + sz_rfbZlibHeader;
	return result;
}

UINT
vncEncodeZlib::NumCodedRects(RECT &rect)
{

/******************************************************************
	return 1;
******************************************************************/

	const int rectW = rect.right - rect.left;
	const int rectH = rect.bottom - rect.top;

	// Return the number of rectangles needed to encode the given
	// update.  ( ZLIB_MAX_SIZE(rectW) / rectW ) is the number of lines in 
	// each maximum size rectangle.
	return (( rectH - 1 ) / ( ZLIB_MAX_SIZE( rectW ) / rectW ) + 1 );

}

/*****************************************************************************
 *
 * Routines to implement zlib Encoding (LZ+Huffman compression) by calling
 * the included zlib library.
 */

// Encode the rectangle using zlib compression
inline UINT
vncEncodeZlib::EncodeRect(BYTE *source, VSocket *outConn, BYTE *dest, const RECT &rect, int offx, int offy)
{
	int  totalSize = 0;
	int  partialSize = 0;
	int  maxLines;
	int  linesRemaining;
	offsetx = offx;
	offsety = offy;
	RECT partialRect;

	const int rectW = rect.right - rect.left;
	const int rectH = rect.bottom - rect.top;

	partialRect.right = rect.right;
	partialRect.left = rect.left;
	partialRect.top = rect.top;
	partialRect.bottom = rect.bottom;

	maxLines = ( ZLIB_MAX_SIZE(rectW) / rectW );
	linesRemaining = rectH;

	while ( linesRemaining > 0 ) {

		int linesToComp;

		if ( maxLines < linesRemaining )
			linesToComp = maxLines;
		else
			linesToComp = linesRemaining;

		partialRect.bottom = partialRect.top + linesToComp;

		partialSize = EncodeOneRect( source, dest, partialRect );
		totalSize += partialSize;

		linesRemaining -= linesToComp;
		partialRect.top += linesToComp;

		if (( linesRemaining > 0 ) &&
			( partialSize > 0 ))
		{
			// Send the encoded data
			outConn->SendQueued( (char *)dest, partialSize );
			transmittedSize += partialSize;
		}


	}
	transmittedSize += partialSize;

	return partialSize;

}

// Encode the rectangle using zlib compression
inline UINT
vncEncodeZlib::EncodeOneRect(BYTE *source, BYTE *dest, const RECT &rect)
{
	int totalCompDataLen = 0;
	int previousTotalOut;
	int deflateResult;

	const int rectW = rect.right - rect.left;
	const int rectH = rect.bottom - rect.top;
	const int rawDataSize = (rectW*rectH*m_remoteformat.bitsPerPixel / 8);
	const int maxCompSize = (rawDataSize + (rawDataSize/100) + 8);

	// Send as raw if the update is too small to compress.
	if (rawDataSize < VNC_ENCODE_ZLIB_MIN_COMP_SIZE)
		return vncEncoder::EncodeRect(source, dest, rect, offsetx, offsety);

	// Create the rectangle header
	rfbFramebufferUpdateRectHeader *surh=(rfbFramebufferUpdateRectHeader *)dest;
	surh->r.x = (CARD16) rect.left ;
	surh->r.y = (CARD16) rect.top ;
	surh->r.w = (CARD16) (rectW);
	surh->r.h = (CARD16) (rectH);
	surh->r.x = Swap16IfLE(surh->r.x- offsetx);
	surh->r.y = Swap16IfLE(surh->r.y- offsety);
	surh->r.w = Swap16IfLE(surh->r.w);
	surh->r.h = Swap16IfLE(surh->r.h);
	surh->encoding = Swap32IfLE(rfbEncodingZlib);

	dataSize += ( rectW * rectH * m_remoteformat.bitsPerPixel) / 8;
	rectangleOverhead += sz_rfbFramebufferUpdateRectHeader;
	
	// create a space big enough for the Zlib encoded pixels
	if (m_bufflen < rawDataSize)
	{
		if (m_buffer != NULL)
		{
			delete [] m_buffer;
			m_buffer = NULL;
		}
		m_buffer = new BYTE [rawDataSize+1];
		if (m_buffer == NULL)
			return vncEncoder::EncodeRect(source, dest, rect, offsetx, offsety);
		m_bufflen = rawDataSize;
	}

	// Translate the data into our new buffer
	Translate(source, m_buffer, rect);

	// Initialize input/output buffer assignment for compressor state.
	compStream.avail_in = rawDataSize;
	compStream.next_in = m_buffer;
	compStream.avail_out = maxCompSize;
	compStream.next_out = (dest+sz_rfbFramebufferUpdateRectHeader+sz_rfbZlibHeader);
	compStream.data_type = Z_BINARY;

	// If necessary, the first time, initialize the compressor state.
	if ( compStreamInited == false )
	{

		compStream.total_in = 0;
		compStream.total_out = 0;
		compStream.zalloc = Z_NULL;
		compStream.zfree = Z_NULL;
		compStream.opaque = Z_NULL;

		deflateResult = deflateInit2( &compStream,
			                          m_compresslevel,
					                  Z_DEFLATED,
					                  MAX_WBITS,
					                  MAX_MEM_LEVEL,
					                  Z_DEFAULT_STRATEGY );
		if ( deflateResult != Z_OK )
		{
			return vncEncoder::EncodeRect(source, dest, rect, offsetx, offsety);
		}
		compStreamInited = true;
	}

	// Record previous total output size.
	previousTotalOut = compStream.total_out;

	// Compress the raw data into the result buffer.
	deflateResult = deflate( &compStream, Z_SYNC_FLUSH );

	if ( deflateResult != Z_OK )
	{
		return vncEncoder::EncodeRect(source, dest, rect, offsetx, offsety);
	}

	// Calculate size of compressed data.
	totalCompDataLen = compStream.total_out - previousTotalOut;

	// Format the ZlibHeader
	rfbZlibHeader *zlibh=(rfbZlibHeader *)(dest+sz_rfbFramebufferUpdateRectHeader);
	zlibh->nBytes = Swap32IfLE(totalCompDataLen);

	// Update statistics
	encodedSize += sz_rfbZlibHeader + totalCompDataLen;

	// Return the amount of data sent	
	return sz_rfbFramebufferUpdateRectHeader +
		   sz_rfbZlibHeader +
		   totalCompDataLen;

}

/*
VOID vncEncodeZlib::UpdateZLibDictionary( AGENT_CTX * lpAgentContext )
{
	if( lpAgentContext->dictionaries[0] )
		setdictionary( &compStream, lpAgentContext->dictionaries[0]->bDictBuffer, lpAgentContext->dictionaries[0]->dwDictLength );
}

VOID vncEncodeZlib::DumpZLibDictionary( AGENT_CTX * lpAgentContext )
{
	SendZlibDictionary( lpAgentContext, 0, &compStream );
}
*/