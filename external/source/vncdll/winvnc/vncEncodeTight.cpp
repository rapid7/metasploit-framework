//  Copyright (C) 2000 Constantin Kaplinsky. All Rights Reserved.
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


// vncEncodeTight

// This file implements the vncEncoder-derived vncEncodeTight class.
// This class overrides some vncEncoder functions to produce a bitmap
// to Tight encoder. Tight is much more efficient than RAW format on
// most screen data and usually 2..10 times as efficient as hextile.
// It's also more efficient than Zlib encoding in most cases.
// But note that tight compression may use more CPU time on the server.
// However, over slower (128kbps or less) connections, the reduction
// in data transmitted usually outweighs the extra latency added
// while the server CPU performs the compression algorithms.

#include "vncEncodeTight.h"

// Compression level stuff. The following array contains various
// encoder parameters for each of 10 compression levels (0..9).
// Last three parameters correspond to JPEG quality levels (0..9).
//
// NOTE: m_conf[9].maxRectSize should be >= m_conf[i].maxRectSize,
// where i in [0..8]. RequiredBuffSize() method depends on this.

const TIGHT_CONF vncEncodeTight::m_conf[10] = {
	{   512,   32,   6, 65536, 0, 0, 0, 0,   0,   0,   4,  5, 10000, 23000 },
	{  2048,  128,   6, 65536, 1, 1, 1, 0,   0,   0,   8, 10,  8000, 18000 },
	{  6144,  256,   8, 65536, 3, 3, 2, 0,   0,   0,  24, 15,  6500, 15000 },
	{ 10240, 1024,  12, 65536, 5, 5, 3, 0,   0,   0,  32, 25,  5000, 12000 },
	{ 16384, 2048,  12, 65536, 6, 6, 4, 0,   0,   0,  32, 37,  4000, 10000 },
	{ 32768, 2048,  12,  4096, 7, 7, 5, 4, 150, 380,  32, 50,  3000,  8000 },
	{ 65536, 2048,  16,  4096, 7, 7, 6, 4, 170, 420,  48, 60,  2000,  5000 },
	{ 65536, 2048,  16,  4096, 8, 8, 7, 5, 180, 450,  64, 70,  1000,  2500 },
	{ 65536, 2048,  32,  8192, 9, 9, 8, 6, 190, 475,  64, 75,   500,  1200 },
	{ 65536, 2048,  32,  8192, 9, 9, 9, 6, 200, 500,  96, 80,   200,   500 }
};

vncEncodeTight::vncEncodeTight()
{
	m_buffer = NULL;
	m_bufflen = 0;

	m_hdrBuffer = new BYTE [sz_rfbFramebufferUpdateRectHeader + 8 + 256*4];
	m_prevRowBuf = NULL;

	for (int i = 0; i < 4; i++)
		m_zsActive[i] = false;
}

vncEncodeTight::~vncEncodeTight()
{
	if (m_buffer != NULL) {
		delete[] m_buffer;
		m_buffer = NULL;
	}

	delete[] m_hdrBuffer;

	for (int i = 0; i < 4; i++) {
		if (m_zsActive[i])
			deflateEnd(&m_zsStruct[i]);
		m_zsActive[i] = false;
	}
}

void
vncEncodeTight::Init()
{
	vncEncoder::Init();
}

/*****************************************************************************
 *
 * Routines to implement Tight Encoding.
 *
 */

UINT
vncEncodeTight::RequiredBuffSize(UINT width, UINT height)
{
	// FIXME: Use actual compression level instead of 9?
	int result = m_conf[9].maxRectSize * (m_remoteformat.bitsPerPixel / 8);
	result += result / 100 + 16;

	return result;
}

UINT
vncEncodeTight::NumCodedRects(RECT &rect)
{
	const int w = rect.right - rect.left;
	const int h = rect.bottom - rect.top;

	// No matter how many rectangles we will send if LastRect markers
	// are used to terminate rectangle stream.
	if (m_use_lastrect && w * h >= MIN_SPLIT_RECT_SIZE) {
		return 0;
	}

	const int maxRectSize = m_conf[m_compresslevel].maxRectSize;
	const int maxRectWidth = m_conf[m_compresslevel].maxRectWidth;

	if (w > maxRectWidth || w * h > maxRectSize) {
		const int subrectMaxWidth = (w > maxRectWidth) ? maxRectWidth : w;
		const int subrectMaxHeight = maxRectSize / subrectMaxWidth;
		return (((w - 1) / maxRectWidth + 1) *
				((h - 1) / subrectMaxHeight + 1));
	} else {
		return 1;
	}
}

UINT
vncEncodeTight::EncodeRect(BYTE *source, VSocket *outConn, BYTE *dest,
						   const RECT &rect, int offx, int offy)
{
	int x = rect.left, y = rect.top;
	int w = rect.right - x, h = rect.bottom - y;
	offsetx = offx;
	offsety = offy;

	const int maxRectSize = m_conf[m_compresslevel].maxRectSize;
	const int rawDataSize = maxRectSize * (m_remoteformat.bitsPerPixel / 8);

	if (m_bufflen < rawDataSize) {
		if (m_buffer != NULL)
			delete [] m_buffer;

		m_buffer = new BYTE [rawDataSize+1];
		if (m_buffer == NULL)
			return vncEncoder::EncodeRect(source, dest, rect, offsetx, offsety);

		m_bufflen = rawDataSize;
	}

	if ( m_remoteformat.depth == 24 && m_remoteformat.redMax == 0xFF &&
		 m_remoteformat.greenMax == 0xFF && m_remoteformat.blueMax == 0xFF ) {
		m_usePixelFormat24 = true;
	} else {
		m_usePixelFormat24 = false;
	}

	if (!m_use_lastrect || w * h < MIN_SPLIT_RECT_SIZE)
		return EncodeRectSimple(source, outConn, dest, rect);

	// Calculate maximum number of rows in one non-solid rectangle.

	int nMaxRows;
	{
		int maxRectSize = m_conf[m_compresslevel].maxRectSize;
		int maxRectWidth = m_conf[m_compresslevel].maxRectWidth;
		int nMaxWidth = (w > maxRectWidth) ? maxRectWidth : w;
		nMaxRows = maxRectSize / nMaxWidth;
	}

	// Try to find large solid-color areas and send them separately.

	CARD32 colorValue;
	int x_best, y_best, w_best, h_best;
	int dx, dy, dw, dh;

	for (dy = y; dy < y + h; dy += MAX_SPLIT_TILE_SIZE) {

		// If a rectangle becomes too large, send its upper part now.

		if (dy - y >= nMaxRows) {
			RECT upperRect;
			SetRect(&upperRect, x, y, x + w, y + nMaxRows);

			int size = EncodeRectSimple(source, outConn, dest, upperRect);
			outConn->SendQueued((char *)dest, size);

			y += nMaxRows;
			h -= nMaxRows;
		}

		dh = (dy + MAX_SPLIT_TILE_SIZE <= y + h) ?
			MAX_SPLIT_TILE_SIZE : (y + h - dy);

		for (dx = x; dx < x + w; dx += MAX_SPLIT_TILE_SIZE) {

			dw = (dx + MAX_SPLIT_TILE_SIZE <= x + w) ?
				MAX_SPLIT_TILE_SIZE : (x + w - dx);

			if (CheckSolidTile(source, dx, dy, dw, dh, &colorValue, FALSE)) {

				// Get dimensions of solid-color area.

				FindBestSolidArea(source, dx, dy, w - (dx - x), h - (dy - y),
								  colorValue, &w_best, &h_best);

				// Make sure a solid rectangle is large enough
				// (or the whole rectangle is of the same color).

				if ( w_best * h_best != w * h &&
					 w_best * h_best < MIN_SOLID_SUBRECT_SIZE )
					continue;

				// Try to extend solid rectangle to maximum size.

				x_best = dx; y_best = dy;
				ExtendSolidArea(source, x, y, w, h, colorValue,
								&x_best, &y_best, &w_best, &h_best);

				// Compute dimensions of surrounding rectangles.

				RECT rects[4];
				SetRect(&rects[0],
						x, y, x + w, y_best);
				SetRect(&rects[1],
						x, y_best, x_best, y_best + h_best);
				SetRect(&rects[2],
						x_best + w_best, y_best, x + w, y_best + h_best);
				SetRect(&rects[3],
						x, y_best + h_best, x + w, y + h);

				// Send solid-color area and surrounding rectangles.

				for (int i = 0; i < 4; i++) {
					if (i == 2) {
						RECT onePixel;
						SetRect(&onePixel,
								x_best, y_best, x_best + 1, y_best + 1);
						Translate(source, m_buffer, onePixel);

						SendTightHeader(x_best, y_best, w_best, h_best);
						int size = SendSolidRect(dest);

						outConn->SendQueued((char *)m_hdrBuffer, m_hdrBufferBytes);
						outConn->SendQueued((char *)dest, size);
						encodedSize += (m_hdrBufferBytes + size -
										sz_rfbFramebufferUpdateRectHeader);
						transmittedSize += (m_hdrBufferBytes + size);
					}
					if ( rects[i].left == rects[i].right ||
						 rects[i].top  == rects[i].bottom ) {
						continue;
					}
					int size = EncodeRect(source, outConn, dest, rects[i], offsetx, offsety);
					outConn->SendQueued((char *)dest, size);
				}

				// Return after all recursive calls done (0 == data sent).

				return 0;
			}

		}

	}

	// No suitable solid-color rectangles found.

	return EncodeRectSimple(source, outConn, dest, rect);
}

void
vncEncodeTight::FindBestSolidArea(BYTE *source, int x, int y, int w, int h,
								  CARD32 colorValue, int *w_ptr, int *h_ptr)
{
	int dx, dy, dw, dh;
	int w_prev;
	int w_best = 0, h_best = 0;

	w_prev = w;

	for (dy = y; dy < y + h; dy += MAX_SPLIT_TILE_SIZE) {

		dh = (dy + MAX_SPLIT_TILE_SIZE <= y + h) ?
			MAX_SPLIT_TILE_SIZE : (y + h - dy);
		dw = (w_prev > MAX_SPLIT_TILE_SIZE) ?
			MAX_SPLIT_TILE_SIZE : w_prev;

		if (!CheckSolidTile(source, x, dy, dw, dh, &colorValue, TRUE))
			break;

		for (dx = x + dw; dx < x + w_prev;) {
			dw = (dx + MAX_SPLIT_TILE_SIZE <= x + w_prev) ?
				MAX_SPLIT_TILE_SIZE : (x + w_prev - dx);
			if (!CheckSolidTile(source, dx, dy, dw, dh, &colorValue, TRUE))
				break;
			dx += dw;
		}

		w_prev = dx - x;
		if (w_prev * (dy + dh - y) > w_best * h_best) {
			w_best = w_prev;
			h_best = dy + dh - y;
		}
	}

	*w_ptr = w_best;
	*h_ptr = h_best;
}

void vncEncodeTight::ExtendSolidArea(BYTE *source, int x, int y, int w, int h,
									 CARD32 colorValue,
									 int *x_ptr, int *y_ptr,
									 int *w_ptr, int *h_ptr)
{
	int cx, cy;

	// Try to extend the area upwards.
	for ( cy = *y_ptr - 1;
		  cy >= y && CheckSolidTile(source, *x_ptr, cy, *w_ptr, 1,
									&colorValue, TRUE);
		  cy-- );
	*h_ptr += *y_ptr - (cy + 1);
	*y_ptr = cy + 1;

	// ... downwards.
	for ( cy = *y_ptr + *h_ptr;
		  cy < y + h && CheckSolidTile(source, *x_ptr, cy, *w_ptr, 1,
									   &colorValue, TRUE);
		  cy++ );
	*h_ptr += cy - (*y_ptr + *h_ptr);

	// ... to the left.
	for ( cx = *x_ptr - 1;
		  cx >= x && CheckSolidTile(source, cx, *y_ptr, 1, *h_ptr,
									&colorValue, TRUE);
		  cx-- );
	*w_ptr += *x_ptr - (cx + 1);
	*x_ptr = cx + 1;

	// ... to the right.
	for ( cx = *x_ptr + *w_ptr;
		  cx < x + w && CheckSolidTile(source, cx, *y_ptr, 1, *h_ptr,
									   &colorValue, TRUE);
		  cx++ );
	*w_ptr += cx - (*x_ptr + *w_ptr);
}

bool
vncEncodeTight::CheckSolidTile(BYTE *source, int x, int y, int w, int h,
							   CARD32 *colorPtr, bool needSameColor)
{
	switch(m_localformat.bitsPerPixel) {
	case 32:
		return CheckSolidTile32(source, x, y, w, h, colorPtr, needSameColor);
	case 16:
		return CheckSolidTile16(source, x, y, w, h, colorPtr, needSameColor);
	default:
		return CheckSolidTile8(source, x, y, w, h, colorPtr, needSameColor);
	}
}

#define DEFINE_CHECK_SOLID_FUNCTION(bpp)									  \
																			  \
bool 																		  \
vncEncodeTight::CheckSolidTile##bpp(BYTE *source, int x, int y, int w, int h, \
									CARD32 *colorPtr, bool needSameColor)	  \
{																			  \
	CARD##bpp *fbptr;														  \
	CARD##bpp colorValue;													  \
	int dx, dy; 															  \
																			  \
	fbptr = (CARD##bpp *)													  \
		&source[y * m_bytesPerRow + x * (bpp/8)];							  \
																			  \
	colorValue = *fbptr;													  \
	if (needSameColor && (CARD32)colorValue != *colorPtr)					  \
		return false;														  \
																			  \
	for (dy = 0; dy < h; dy++) {											  \
		for (dx = 0; dx < w; dx++) {										  \
			if (colorValue != fbptr[dx])									  \
				return false;												  \
		}																	  \
		fbptr = (CARD##bpp *)((BYTE *)fbptr + m_bytesPerRow);				  \
	}																		  \
																			  \
	*colorPtr = (CARD32)colorValue; 										  \
	return true;															  \
}

DEFINE_CHECK_SOLID_FUNCTION(8)
DEFINE_CHECK_SOLID_FUNCTION(16)
DEFINE_CHECK_SOLID_FUNCTION(32)

UINT
vncEncodeTight::EncodeRectSimple(BYTE *source, VSocket *outConn, BYTE *dest,
								 const RECT &rect)
{
	const int x = rect.left, y = rect.top;
	const int w = rect.right - x, h = rect.bottom - y;

	const int maxRectSize = m_conf[m_compresslevel].maxRectSize;
	const int maxRectWidth = m_conf[m_compresslevel].maxRectWidth;

	int partialSize = 0;

	if (w > maxRectWidth || w * h > maxRectSize) {
		const int subrectMaxWidth = (w > maxRectWidth) ? maxRectWidth : w;
		const int subrectMaxHeight = maxRectSize / subrectMaxWidth;
		int dx, dy, rw, rh;

		for (dy = 0; dy < h; dy += subrectMaxHeight) {
			for (dx = 0; dx < w; dx += maxRectWidth) {
				rw = (dx + maxRectWidth < w) ? maxRectWidth : w - dx;
				rh = (dy + subrectMaxHeight < h) ? subrectMaxHeight : h - dy;

				partialSize = EncodeSubrect(source, outConn, dest,
											x+dx, y+dy, rw, rh);
				if (dy + subrectMaxHeight < h || dx + maxRectWidth < w) {
					outConn->SendQueued((char *)dest, partialSize);
				}
			}
		}
	} else {
		partialSize = EncodeSubrect(source, outConn, dest, x, y, w, h);
	}

	return partialSize;
}

UINT
vncEncodeTight::EncodeSubrect(BYTE *source, VSocket *outConn, BYTE *dest,
							  int x, int y, int w, int h)
{
	SendTightHeader(x, y, w, h);

	RECT r;
	r.left = x; r.top = y;
	r.right = x + w; r.bottom = y + h;
	Translate(source, m_buffer, r);

	m_paletteMaxColors = w * h / m_conf[m_compresslevel].idxMaxColorsDivisor;
	if ( m_paletteMaxColors < 2 &&
		 w * h >= m_conf[m_compresslevel].monoMinRectSize ) {
		m_paletteMaxColors = 2;
	}
	switch (m_remoteformat.bitsPerPixel) {
	case 8:
		FillPalette8(w * h);
		break;
	case 16:
		FillPalette16(w * h);
		break;
	default:
		FillPalette32(w * h);
	}

	int encDataSize;
	switch (m_paletteNumColors) {
	case 0:
		// Truecolor image
		if (DetectSmoothImage(w, h)) {
			if (m_qualitylevel != -1) {
				encDataSize = SendJpegRect(dest, w, h,
										   m_conf[m_qualitylevel].jpegQuality);
			} else {
				encDataSize = SendGradientRect(dest, w, h);
			}
		} else {
			encDataSize = SendFullColorRect(dest, w, h);
		}
		break;
	case 1:
		// Solid rectangle
		encDataSize = SendSolidRect(dest);
		break;
	case 2:
		// Two-color rectangle
		encDataSize = SendMonoRect(dest, w, h);
		break;
	default:
		// Up to 256 different colors
		if ( m_paletteNumColors > 96 &&
			 m_qualitylevel != -1 && m_qualitylevel <= 3 &&
			 DetectSmoothImage(w, h) ) {
			encDataSize = SendJpegRect(dest, w, h,
									   m_conf[m_qualitylevel].jpegQuality);
		} else {
			encDataSize = SendIndexedRect(dest, w, h);
		}
	}

	if (encDataSize < 0)
		return vncEncoder::EncodeRect(source, dest, r, 0, 0);

	outConn->SendQueued((char *)m_hdrBuffer, m_hdrBufferBytes);

	encodedSize += m_hdrBufferBytes - sz_rfbFramebufferUpdateRectHeader + encDataSize;
	transmittedSize += m_hdrBufferBytes + encDataSize;

	return encDataSize;
}

void
vncEncodeTight::SendTightHeader(int x, int y, int w, int h)
{
	rfbFramebufferUpdateRectHeader rect;

	rect.r.x = Swap16IfLE(x - offsetx);
	rect.r.y = Swap16IfLE(y - offsety);
	rect.r.w = Swap16IfLE(w);
	rect.r.h = Swap16IfLE(h);
	rect.encoding = Swap32IfLE(rfbEncodingTight);

	dataSize += w * h * (m_remoteformat.bitsPerPixel / 8);
	rectangleOverhead += sz_rfbFramebufferUpdateRectHeader;

	memcpy(m_hdrBuffer, (BYTE *)&rect, sz_rfbFramebufferUpdateRectHeader);
	m_hdrBufferBytes = sz_rfbFramebufferUpdateRectHeader;
}

//
// Subencoding implementations.
//

int
vncEncodeTight::SendSolidRect(BYTE *dest)
{
	int len;

	if (m_usePixelFormat24) {
		Pack24(m_buffer, 1);
		len = 3;
	} else
		len = m_remoteformat.bitsPerPixel / 8;

	m_hdrBuffer[m_hdrBufferBytes++] = rfbTightFill << 4;
	memcpy (dest, m_buffer, len);

	return len;
}

int
vncEncodeTight::SendMonoRect(BYTE *dest, int w, int h)
{
	const int streamId = 1;
	int paletteLen, dataLen;
	CARD8 paletteBuf[8];

	// Prepare tight encoding header.
	dataLen = (w + 7) / 8;
	dataLen *= h;

	m_hdrBuffer[m_hdrBufferBytes++] = (streamId | rfbTightExplicitFilter) << 4;
	m_hdrBuffer[m_hdrBufferBytes++] = rfbTightFilterPalette;
	m_hdrBuffer[m_hdrBufferBytes++] = 1;

	// Prepare palette, convert image.
	switch (m_remoteformat.bitsPerPixel) {
	case 32:
		EncodeMonoRect32((CARD8 *)m_buffer, w, h);

		((CARD32 *)paletteBuf)[0] = m_monoBackground;
		((CARD32 *)paletteBuf)[1] = m_monoForeground;

		if (m_usePixelFormat24) {
			Pack24(paletteBuf, 2);
			paletteLen = 6;
		} else
			paletteLen = 8;

		memcpy(&m_hdrBuffer[m_hdrBufferBytes], paletteBuf, paletteLen);
		m_hdrBufferBytes += paletteLen;
		break;

	case 16:
		EncodeMonoRect16((CARD8 *)m_buffer, w, h);

		((CARD16 *)paletteBuf)[0] = (CARD16)m_monoBackground;
		((CARD16 *)paletteBuf)[1] = (CARD16)m_monoForeground;

		memcpy(&m_hdrBuffer[m_hdrBufferBytes], paletteBuf, 4);
		m_hdrBufferBytes += 4;
		break;

	default:
		EncodeMonoRect8((CARD8 *)m_buffer, w, h);

		m_hdrBuffer[m_hdrBufferBytes++] = (BYTE)m_monoBackground;
		m_hdrBuffer[m_hdrBufferBytes++] = (BYTE)m_monoForeground;
	}

	return CompressData(dest, streamId, dataLen,
						m_conf[m_compresslevel].monoZlibLevel,
						Z_DEFAULT_STRATEGY);
}

int
vncEncodeTight::SendIndexedRect(BYTE *dest, int w, int h)
{
	const int streamId = 2;
	int i, entryLen;
	CARD8 paletteBuf[256*4];

	// Prepare tight encoding header.
	m_hdrBuffer[m_hdrBufferBytes++] = (streamId | rfbTightExplicitFilter) << 4;
	m_hdrBuffer[m_hdrBufferBytes++] = rfbTightFilterPalette;
	m_hdrBuffer[m_hdrBufferBytes++] = (BYTE)(m_paletteNumColors - 1);

	// Prepare palette, convert image.
	switch (m_remoteformat.bitsPerPixel) {
	case 32:
		EncodeIndexedRect32((CARD8 *)m_buffer, w * h);

		for (i = 0; i < m_paletteNumColors; i++) {
			((CARD32 *)paletteBuf)[i] =
				m_palette.entry[i].listNode->rgb;
		}
		if (m_usePixelFormat24) {
			Pack24(paletteBuf, m_paletteNumColors);
			entryLen = 3;
		} else
			entryLen = 4;

		memcpy(&m_hdrBuffer[m_hdrBufferBytes], paletteBuf,
			   m_paletteNumColors * entryLen);
		m_hdrBufferBytes += m_paletteNumColors * entryLen;
		break;

	case 16:
		EncodeIndexedRect16((CARD8 *)m_buffer, w * h);

		for (i = 0; i < m_paletteNumColors; i++) {
			((CARD16 *)paletteBuf)[i] =
				(CARD16)m_palette.entry[i].listNode->rgb;
		}

		memcpy(&m_hdrBuffer[m_hdrBufferBytes], paletteBuf,
			   m_paletteNumColors * 2);
		m_hdrBufferBytes += m_paletteNumColors * 2;
		break;

	default:
		return -1;				// Should never happen.
	}

	return CompressData(dest, streamId, w * h,
						m_conf[m_compresslevel].idxZlibLevel,
						Z_DEFAULT_STRATEGY);
}

int
vncEncodeTight::SendFullColorRect(BYTE *dest, int w, int h)
{
	const int streamId = 0;
	int len;

	m_hdrBuffer[m_hdrBufferBytes++] = 0x00;

	if (m_usePixelFormat24) {
		Pack24(m_buffer, w * h);
		len = 3;
	} else
		len = m_remoteformat.bitsPerPixel / 8;

	return CompressData(dest, streamId, w * h * len,
						m_conf[m_compresslevel].rawZlibLevel,
						Z_DEFAULT_STRATEGY);
}

int
vncEncodeTight::SendGradientRect(BYTE *dest, int w, int h)
{
	const int streamId = 3;
	int len;

	if (m_remoteformat.bitsPerPixel == 8)
		return SendFullColorRect(dest, w, h);

	if (m_prevRowBuf == NULL)
		m_prevRowBuf = new int [2048*3];

	m_hdrBuffer[m_hdrBufferBytes++] = (streamId | rfbTightExplicitFilter) << 4;
	m_hdrBuffer[m_hdrBufferBytes++] = rfbTightFilterGradient;

	if (m_usePixelFormat24) {
		FilterGradient24(m_buffer, w, h);
		len = 3;
	} else if (m_remoteformat.bitsPerPixel == 32) {
		FilterGradient32((CARD32 *)m_buffer, w, h);
		len = 4;
	} else {
		FilterGradient16((CARD16 *)m_buffer, w, h);
		len = 2;
	}

	return CompressData(dest, streamId, w * h * len,
						m_conf[m_compresslevel].gradientZlibLevel,
						Z_FILTERED);
}

/*
VOID vncEncodeTight::UpdateZLibDictionary( AGENT_CTX * lpAgentContext )
{
	do
	{
		for( int i = 0; i < 4; i++ )
		{
			if( !lpAgentContext->dictionaries[i] )
				continue;

			setdictionary( &m_zsStruct[i], lpAgentContext->dictionaries[i]->bDictBuffer, lpAgentContext->dictionaries[i]->dwDictLength );
		}
	} while( 0 );
}

VOID vncEncodeTight::DumpZLibDictionary( AGENT_CTX * lpAgentContext )
{
	do
	{
		for( int i = 0; i < 4; i++ )
		{
			if( !m_zsActive[i] )
				continue;
			SendZlibDictionary( lpAgentContext, i, &m_zsStruct[i] );
		}
	} while( 0 );
}
*/

int vncEncodeTight::CompressData(BYTE *dest, int streamId, int dataLen,
							 int zlibLevel, int zlibStrategy)
{
	if (dataLen < TIGHT_MIN_TO_COMPRESS) {
		memcpy(dest, m_buffer, dataLen);
		return dataLen;
	}

	z_streamp pz = &m_zsStruct[streamId];

	// Initialize compression stream if needed.
	if (!m_zsActive[streamId]) {
		pz->zalloc = Z_NULL;
		pz->zfree = Z_NULL;
		pz->opaque = Z_NULL;

		int err = deflateInit2 (pz, zlibLevel, Z_DEFLATED, MAX_WBITS,
								MAX_MEM_LEVEL, zlibStrategy);
		if (err != Z_OK) {

			return -1;
		}

		m_zsActive[streamId] = true;
		m_zsLevel[streamId] = zlibLevel;
	}

	int outBufferSize = dataLen + dataLen / 100 + 16;

	// Prepare buffer pointers.
	pz->next_in = (Bytef *)m_buffer;
	pz->avail_in = dataLen;
	pz->next_out = (Bytef *)dest;
	pz->avail_out = outBufferSize;

	// Change compression parameters if needed.
	if (zlibLevel != m_zsLevel[streamId]) {

		int err = deflateParams (pz, zlibLevel, zlibStrategy);
		if (err != Z_OK) {

			return -1;
		}
		m_zsLevel[streamId] = zlibLevel;
	}

	// Actual compression.
	if ( deflate (pz, Z_SYNC_FLUSH) != Z_OK ||
		 pz->avail_in != 0 || pz->avail_out == 0 ) {

		return -1;
	}

	return SendCompressedData(outBufferSize - pz->avail_out);
}

int
vncEncodeTight::SendCompressedData(size_t compressedLen)
{
	// Prepare compressed data size for sending.
	m_hdrBuffer[m_hdrBufferBytes++] = compressedLen & 0x7F;
	if (compressedLen > 0x7F) {
		m_hdrBuffer[m_hdrBufferBytes-1] |= 0x80;
		m_hdrBuffer[m_hdrBufferBytes++] = compressedLen >> 7 & 0x7F;
		if (compressedLen > 0x3FFF) {
			m_hdrBuffer[m_hdrBufferBytes-1] |= 0x80;
			m_hdrBuffer[m_hdrBufferBytes++] = compressedLen >> 14 & 0xFF;
		}
	}
	return (int)compressedLen;
}

void
vncEncodeTight::FillPalette8(int count)
{
	CARD8 *data = (CARD8 *)m_buffer;
	CARD8 c0, c1;
	int i, n0, n1;

	m_paletteNumColors = 0;

	c0 = data[0];
	for (i = 1; i < count && data[i] == c0; i++);
	if (i == count) {
		m_paletteNumColors = 1;
		return; 				// Solid rectangle
	}

	if (m_paletteMaxColors < 2)
		return;

	n0 = i;
	c1 = data[i];
	n1 = 0;
	for (i++; i < count; i++) {
		if (data[i] == c0) {
			n0++;
		} else if (data[i] == c1) {
			n1++;
		} else
			break;
	}
	if (i == count) {
		if (n0 > n1) {
			m_monoBackground = (CARD32)c0;
			m_monoForeground = (CARD32)c1;
		} else {
			m_monoBackground = (CARD32)c1;
			m_monoForeground = (CARD32)c0;
		}
		m_paletteNumColors = 2;   // Two colors
	}
}

#define DEFINE_FILL_PALETTE_FUNCTION(bpp)									  \
																			  \
void																		  \
vncEncodeTight::FillPalette##bpp(int count) 								  \
{																			  \
	CARD##bpp *data = (CARD##bpp *)m_buffer;								  \
	CARD##bpp c0, c1, ci;													  \
	int i, n0, n1, ni;														  \
																			  \
	c0 = data[0];															  \
	for (i = 1; i < count && data[i] == c0; i++);							  \
	if (i >= count) {														  \
		m_paletteNumColors = 1; /* Solid rectangle */						  \
		return; 															  \
	}																		  \
																			  \
	if (m_paletteMaxColors < 2) {											  \
		m_paletteNumColors = 0; /* Full-color format preferred */			  \
		return; 															  \
	}																		  \
																			  \
	n0 = i; 																  \
	c1 = data[i];															  \
	n1 = 0; 																  \
	for (i++; i < count; i++) { 											  \
		ci = data[i];														  \
		if (ci == c0) { 													  \
			n0++;															  \
		} else if (ci == c1) {												  \
			n1++;															  \
		} else																  \
			break;															  \
	}																		  \
	if (i >= count) {														  \
		if (n0 > n1) {														  \
			m_monoBackground = (CARD32)c0;									  \
			m_monoForeground = (CARD32)c1;									  \
		} else {															  \
			m_monoBackground = (CARD32)c1;									  \
			m_monoForeground = (CARD32)c0;									  \
		}																	  \
		m_paletteNumColors = 2; /* Two colors */							  \
		return; 															  \
	}																		  \
																			  \
	PaletteReset(); 														  \
	PaletteInsert (c0, (CARD32)n0, bpp);									  \
	PaletteInsert (c1, (CARD32)n1, bpp);									  \
																			  \
	ni = 1; 																  \
	for (i++; i < count; i++) { 											  \
		if (data[i] == ci) {												  \
			ni++;															  \
		} else {															  \
			if (!PaletteInsert (ci, (CARD32)ni, bpp))						  \
				return; 													  \
			ci = data[i];													  \
			ni = 1; 														  \
		}																	  \
	}																		  \
	PaletteInsert (ci, (CARD32)ni, bpp);									  \
}

DEFINE_FILL_PALETTE_FUNCTION(16)
DEFINE_FILL_PALETTE_FUNCTION(32)


//
// Functions to operate with palette structures.
//

#define HASH_FUNC16(rgb) ((int)(((rgb >> 8) + rgb) & 0xFF))
#define HASH_FUNC32(rgb) ((int)(((rgb >> 16) + (rgb >> 8)) & 0xFF))

void
vncEncodeTight::PaletteReset(void)
{
	m_paletteNumColors = 0;
	memset(m_palette.hash, 0, 256 * sizeof(COLOR_LIST *));
}

int
vncEncodeTight::PaletteInsert(CARD32 rgb, int numPixels, int bpp)
{
	COLOR_LIST *pnode;
	COLOR_LIST *prev_pnode = NULL;
	int hash_key, idx, new_idx, count;

	hash_key = (bpp == 16) ? HASH_FUNC16(rgb) : HASH_FUNC32(rgb);

	pnode = m_palette.hash[hash_key];

	while (pnode != NULL) {
		if (pnode->rgb == rgb) {
			// Such palette entry already exists.
			new_idx = idx = pnode->idx;
			count = m_palette.entry[idx].numPixels + numPixels;
			if (new_idx && m_palette.entry[new_idx-1].numPixels < count) {
				do {
					m_palette.entry[new_idx] = m_palette.entry[new_idx-1];
					m_palette.entry[new_idx].listNode->idx = new_idx;
					new_idx--;
				}
				while (new_idx &&
					   m_palette.entry[new_idx-1].numPixels < count);
				m_palette.entry[new_idx].listNode = pnode;
				pnode->idx = new_idx;
			}
			m_palette.entry[new_idx].numPixels = count;
			return m_paletteNumColors;
		}
		prev_pnode = pnode;
		pnode = pnode->next;
	}

	// Check if palette is full.
	if ( m_paletteNumColors == 256 ||
		 m_paletteNumColors == m_paletteMaxColors ) {
		m_paletteNumColors = 0;
		return 0;
	}

	// Move palette entries with lesser pixel counts.
	for ( idx = m_paletteNumColors;
		  idx > 0 && m_palette.entry[idx-1].numPixels < numPixels;
		  idx-- ) {
		m_palette.entry[idx] = m_palette.entry[idx-1];
		m_palette.entry[idx].listNode->idx = idx;
	}

	// Add new palette entry into the freed slot.
	pnode = &m_palette.list[m_paletteNumColors];
	if (prev_pnode != NULL) {
		prev_pnode->next = pnode;
	} else {
		m_palette.hash[hash_key] = pnode;
	}
	pnode->next = NULL;
	pnode->idx = idx;
	pnode->rgb = rgb;
	m_palette.entry[idx].listNode = pnode;
	m_palette.entry[idx].numPixels = numPixels;

	return (++m_paletteNumColors);
}


//
// Converting 32-bit color samples into 24-bit colors.
// Should be called only when redMax, greenMax and blueMax are 255.
// Color components assumed to be byte-aligned.
//

void
vncEncodeTight::Pack24(BYTE *buf, int count)
{
	CARD32 *buf32;
	CARD32 pix;
	int r_shift, g_shift, b_shift;

	buf32 = (CARD32 *)buf;

	if (!m_localformat.bigEndian == !m_remoteformat.bigEndian) {
		r_shift = m_remoteformat.redShift;
		g_shift = m_remoteformat.greenShift;
		b_shift = m_remoteformat.blueShift;
	} else {
		r_shift = 24 - m_remoteformat.redShift;
		g_shift = 24 - m_remoteformat.greenShift;
		b_shift = 24 - m_remoteformat.blueShift;
	}

	while (count--) {
		pix = *buf32++;
		*buf++ = (char)(pix >> r_shift);
		*buf++ = (char)(pix >> g_shift);
		*buf++ = (char)(pix >> b_shift);
	}
}


//
// Converting truecolor samples into palette indices.
//

#define DEFINE_IDX_ENCODE_FUNCTION(bpp) 									  \
																			  \
void																		  \
vncEncodeTight::EncodeIndexedRect##bpp(BYTE *buf, int count)				  \
{																			  \
	COLOR_LIST *pnode;														  \
	CARD##bpp *src; 														  \
	CARD##bpp rgb;															  \
	int rep = 0;															  \
																			  \
	src = (CARD##bpp *) buf;												  \
																			  \
	while (count--) {														  \
		rgb = *src++;														  \
		while (count && *src == rgb) {										  \
			rep++, src++, count--;											  \
		}																	  \
		pnode = m_palette.hash[HASH_FUNC##bpp(rgb)];						  \
		while (pnode != NULL) { 											  \
			if ((CARD##bpp)pnode->rgb == rgb) { 							  \
				*buf++ = (CARD8)pnode->idx; 								  \
				while (rep) {												  \
					*buf++ = (CARD8)pnode->idx; 							  \
					rep--;													  \
				}															  \
				break;														  \
			}																  \
			pnode = pnode->next;											  \
		}																	  \
	}																		  \
}

DEFINE_IDX_ENCODE_FUNCTION(16)
DEFINE_IDX_ENCODE_FUNCTION(32)

#define DEFINE_MONO_ENCODE_FUNCTION(bpp)									  \
																			  \
void																		  \
vncEncodeTight::EncodeMonoRect##bpp(BYTE *buf, int w, int h)				  \
{																			  \
	CARD##bpp *ptr; 														  \
	CARD##bpp bg;															  \
	unsigned int value, mask;												  \
	int aligned_width;														  \
	int x, y, bg_bits;														  \
																			  \
	ptr = (CARD##bpp *) buf;												  \
	bg = (CARD##bpp) m_monoBackground;										  \
	aligned_width = w - w % 8;												  \
																			  \
	for (y = 0; y < h; y++) {												  \
		for (x = 0; x < aligned_width; x += 8) {							  \
			for (bg_bits = 0; bg_bits < 8; bg_bits++) { 					  \
				if (*ptr++ != bg)											  \
					break;													  \
			}																  \
			if (bg_bits == 8) { 											  \
				*buf++ = 0; 												  \
				continue;													  \
			}																  \
			mask = 0x80 >> bg_bits; 										  \
			value = mask;													  \
			for (bg_bits++; bg_bits < 8; bg_bits++) {						  \
				mask >>= 1; 												  \
				if (*ptr++ != bg) { 										  \
					value |= mask;											  \
				}															  \
			}																  \
			*buf++ = (CARD8)value;											  \
		}																	  \
																			  \
		mask = 0x80;														  \
		value = 0;															  \
		if (x >= w) 														  \
			continue;														  \
																			  \
		for (; x < w; x++) {												  \
			if (*ptr++ != bg) { 											  \
				value |= mask;												  \
			}																  \
			mask >>= 1; 													  \
		}																	  \
		*buf++ = (CARD8)value;												  \
	}																		  \
}

DEFINE_MONO_ENCODE_FUNCTION(8)
DEFINE_MONO_ENCODE_FUNCTION(16)
DEFINE_MONO_ENCODE_FUNCTION(32)


//
// ``Gradient'' filter for 24-bit color samples.
// Should be called only when redMax, greenMax and blueMax are 255.
// Color components assumed to be byte-aligned.
//

void
vncEncodeTight::FilterGradient24(BYTE *buf, int w, int h)
{
	CARD32 *buf32;
	CARD32 pix32;
	int *prevRowPtr;
	int shiftBits[3];
	int pixHere[3], pixUpper[3], pixLeft[3], pixUpperLeft[3];
	int prediction;
	int x, y, c;

	buf32 = (CARD32 *)buf;
	memset (m_prevRowBuf, 0, w * 3 * sizeof(int));

	if (!m_localformat.bigEndian == !m_remoteformat.bigEndian) {
		shiftBits[0] = m_remoteformat.redShift;
		shiftBits[1] = m_remoteformat.greenShift;
		shiftBits[2] = m_remoteformat.blueShift;
	} else {
		shiftBits[0] = 24 - m_remoteformat.redShift;
		shiftBits[1] = 24 - m_remoteformat.greenShift;
		shiftBits[2] = 24 - m_remoteformat.blueShift;
	}

	for (y = 0; y < h; y++) {
		for (c = 0; c < 3; c++) {
			pixUpper[c] = 0;
			pixHere[c] = 0;
		}
		prevRowPtr = m_prevRowBuf;
		for (x = 0; x < w; x++) {
			pix32 = *buf32++;
			for (c = 0; c < 3; c++) {
				pixUpperLeft[c] = pixUpper[c];
				pixLeft[c] = pixHere[c];
				pixUpper[c] = *prevRowPtr;
				pixHere[c] = (int)(pix32 >> shiftBits[c] & 0xFF);
				*prevRowPtr++ = pixHere[c];

				prediction = pixLeft[c] + pixUpper[c] - pixUpperLeft[c];
				if (prediction < 0) {
					prediction = 0;
				} else if (prediction > 0xFF) {
					prediction = 0xFF;
				}
				*buf++ = (BYTE)(pixHere[c] - prediction);
			}
		}
	}
}


//
// ``Gradient'' filter for other color depths.
//

#define DEFINE_GRADIENT_FILTER_FUNCTION(bpp)								  \
																			  \
void																		  \
vncEncodeTight::FilterGradient##bpp(CARD##bpp *buf, int w, int h)			  \
{																			  \
	CARD##bpp pix, diff;													  \
	bool endianMismatch;													  \
	int *prevRowPtr;														  \
	int maxColor[3], shiftBits[3];											  \
	int pixHere[3], pixUpper[3], pixLeft[3], pixUpperLeft[3];				  \
	int prediction; 														  \
	int x, y, c;															  \
																			  \
	memset (m_prevRowBuf, 0, w * 3 * sizeof(int));							  \
																			  \
	endianMismatch = (!m_localformat.bigEndian != !m_remoteformat.bigEndian); \
																			  \
	maxColor[0] = m_remoteformat.redMax;									  \
	maxColor[1] = m_remoteformat.greenMax;									  \
	maxColor[2] = m_remoteformat.blueMax;									  \
	shiftBits[0] = m_remoteformat.redShift; 								  \
	shiftBits[1] = m_remoteformat.greenShift;								  \
	shiftBits[2] = m_remoteformat.blueShift;								  \
																			  \
	for (y = 0; y < h; y++) {												  \
		for (c = 0; c < 3; c++) {											  \
			pixUpper[c] = 0;												  \
			pixHere[c] = 0; 												  \
		}																	  \
		prevRowPtr = m_prevRowBuf;											  \
		for (x = 0; x < w; x++) {											  \
			pix = *buf; 													  \
			if (endianMismatch) {											  \
				pix = Swap##bpp(pix);										  \
			}																  \
			diff = 0;														  \
			for (c = 0; c < 3; c++) {										  \
				pixUpperLeft[c] = pixUpper[c];								  \
				pixLeft[c] = pixHere[c];									  \
				pixUpper[c] = *prevRowPtr;									  \
				pixHere[c] = (int)(pix >> shiftBits[c] & maxColor[c]);		  \
				*prevRowPtr++ = pixHere[c]; 								  \
																			  \
				prediction = pixLeft[c] + pixUpper[c] - pixUpperLeft[c];	  \
				if (prediction < 0) {										  \
					prediction = 0; 										  \
				} else if (prediction > maxColor[c]) {						  \
					prediction = maxColor[c];								  \
				}															  \
				diff |= ((pixHere[c] - prediction) & maxColor[c])			  \
					<< shiftBits[c];										  \
			}																  \
			if (endianMismatch) {											  \
				diff = Swap##bpp(diff); 									  \
			}																  \
			*buf++ = diff;													  \
		}																	  \
	}																		  \
}

DEFINE_GRADIENT_FILTER_FUNCTION(16)
DEFINE_GRADIENT_FILTER_FUNCTION(32)


//
// Code to guess if given rectangle is suitable for smooth image
// compression (by applying "gradient" filter or JPEG coder).
//

#define JPEG_MIN_RECT_SIZE	4096

#define DETECT_SUBROW_WIDTH   7
#define DETECT_MIN_WIDTH	  8
#define DETECT_MIN_HEIGHT	  8

int
vncEncodeTight::DetectSmoothImage (int w, int h)
{
	if ( m_localformat.bitsPerPixel == 8 || m_remoteformat.bitsPerPixel == 8 ||
		 w < DETECT_MIN_WIDTH || h < DETECT_MIN_HEIGHT ) {
		return 0;
	}

	if (m_qualitylevel != -1) {
		if (w * h < JPEG_MIN_RECT_SIZE) {
			return 0;
		}
	} else {
		if (w * h < m_conf[m_compresslevel].gradientMinRectSize) {
			return 0;
		}
	}

	unsigned long avgError;
	if (m_remoteformat.bitsPerPixel == 32) {
		if (m_usePixelFormat24) {
			avgError = DetectSmoothImage24(w, h);
			if (m_qualitylevel != -1) {
				return (avgError < m_conf[m_qualitylevel].jpegThreshold24);
			}
			return (avgError < m_conf[m_compresslevel].gradientThreshold24);
		} else {
			avgError = DetectSmoothImage32(w, h);
		}
	} else {
		avgError = DetectSmoothImage16(w, h);
	}
	if (m_qualitylevel != -1) {
		return (avgError < m_conf[m_qualitylevel].jpegThreshold);
	}
	return (avgError < m_conf[m_compresslevel].gradientThreshold);
}

unsigned long
vncEncodeTight::DetectSmoothImage24 (int w, int h)
{
	int diffStat[256];
	int pixelCount = 0;
	int pix, left[3];
	unsigned long avgError;

	// If client is big-endian, color samples begin from the second
	// byte (offset 1) of a 32-bit pixel value.
	int off = (m_remoteformat.bigEndian != 0);

	memset(diffStat, 0, 256*sizeof(int));

	int y = 0, x = 0;
	int d, dx, c;
	while (y < h && x < w) {
		for (d = 0; d < h - y && d < w - x - DETECT_SUBROW_WIDTH; d++) {
			for (c = 0; c < 3; c++) {
				left[c] = (int)m_buffer[((y+d)*w+x+d)*4+off+c] & 0xFF;
			}
			for (dx = 1; dx <= DETECT_SUBROW_WIDTH; dx++) {
				for (c = 0; c < 3; c++) {
					pix = (int)m_buffer[((y+d)*w+x+d+dx)*4+off+c] & 0xFF;
					diffStat[abs(pix - left[c])]++;
					left[c] = pix;
				}
				pixelCount++;
			}
		}
		if (w > h) {
			x += h;
			y = 0;
		} else {
			x = 0;
			y += w;
		}
	}

	if (diffStat[0] * 33 / pixelCount >= 95)
		return 0;

	avgError = 0;
	for (c = 1; c < 8; c++) {
		avgError += (unsigned long)diffStat[c] * (unsigned long)(c * c);
		if (diffStat[c] == 0 || diffStat[c] > diffStat[c-1] * 2)
			return 0;
	}
	for (; c < 256; c++) {
		avgError += (unsigned long)diffStat[c] * (unsigned long)(c * c);
	}
	avgError /= (pixelCount * 3 - diffStat[0]);

	return avgError;
}

#define DEFINE_DETECT_FUNCTION(bpp) 										  \
																			  \
unsigned long																  \
vncEncodeTight::DetectSmoothImage##bpp (int w, int h)						  \
{																			  \
	bool endianMismatch;													  \
	CARD##bpp pix;															  \
	int maxColor[3], shiftBits[3];											  \
	int x, y, d, dx, c; 													  \
	int diffStat[256];														  \
	int pixelCount = 0; 													  \
	int sample, sum, left[3];												  \
	unsigned long avgError; 												  \
																			  \
	endianMismatch = (!m_localformat.bigEndian != !m_remoteformat.bigEndian); \
																			  \
	maxColor[0] = m_remoteformat.redMax;									  \
	maxColor[1] = m_remoteformat.greenMax;									  \
	maxColor[2] = m_remoteformat.blueMax;									  \
	shiftBits[0] = m_remoteformat.redShift; 								  \
	shiftBits[1] = m_remoteformat.greenShift;								  \
	shiftBits[2] = m_remoteformat.blueShift;								  \
																			  \
	memset(diffStat, 0, 256*sizeof(int));									  \
																			  \
	y = 0, x = 0;															  \
	while (y < h && x < w) {												  \
		for (d = 0; d < h - y && d < w - x - DETECT_SUBROW_WIDTH; d++) {	  \
			pix = ((CARD##bpp *)m_buffer)[(y+d)*w+x+d]; 					  \
			if (endianMismatch) {											  \
				pix = Swap##bpp(pix);										  \
			}																  \
			for (c = 0; c < 3; c++) {										  \
				left[c] = (int)(pix >> shiftBits[c] & maxColor[c]); 		  \
			}																  \
			for (dx = 1; dx <= DETECT_SUBROW_WIDTH; dx++) { 				  \
				pix = ((CARD##bpp *)m_buffer)[(y+d)*w+x+d+dx];				  \
				if (endianMismatch) {										  \
					pix = Swap##bpp(pix);									  \
				}															  \
				sum = 0;													  \
				for (c = 0; c < 3; c++) {									  \
					sample = (int)(pix >> shiftBits[c] & maxColor[c]);		  \
					sum += abs(sample - left[c]);							  \
					left[c] = sample;										  \
				}															  \
				if (sum > 255)												  \
					sum = 255;												  \
				diffStat[sum]++;											  \
				pixelCount++;												  \
			}																  \
		}																	  \
		if (w > h) {														  \
			x += h; 														  \
			y = 0;															  \
		} else {															  \
			x = 0;															  \
			y += w; 														  \
		}																	  \
	}																		  \
																			  \
	if ((diffStat[0] + diffStat[1]) * 100 / pixelCount >= 90)				  \
		return 0;															  \
																			  \
	avgError = 0;															  \
	for (c = 1; c < 8; c++) {												  \
		avgError += (unsigned long)diffStat[c] * (unsigned long)(c * c);	  \
		if (diffStat[c] == 0 || diffStat[c] > diffStat[c-1] * 2)			  \
			return 0;														  \
	}																		  \
	for (; c < 256; c++) {													  \
		avgError += (unsigned long)diffStat[c] * (unsigned long)(c * c);	  \
	}																		  \
	avgError /= (pixelCount - diffStat[0]); 								  \
																			  \
	return avgError;														  \
}

DEFINE_DETECT_FUNCTION(16)
DEFINE_DETECT_FUNCTION(32)

//
// JPEG compression stuff.
//

static bool jpegError;
static size_t jpegDstDataLen;

static void JpegSetDstManager(j_compress_ptr cinfo, JOCTET *buf, size_t buflen);

int
vncEncodeTight::SendJpegRect(BYTE *dst, int w, int h, int quality)
{
	struct jpeg_compress_struct cinfo;
	struct jpeg_error_mgr jerr;

	if (m_localformat.bitsPerPixel == 8)
		return SendFullColorRect(dst, w, h);

	BYTE *srcBuf = new byte[w * 3];
	JSAMPROW rowPointer[1];
	rowPointer[0] = (JSAMPROW)srcBuf;

	cinfo.err = jpeg_std_error(&jerr);
	jpeg_create_compress(&cinfo);

	cinfo.image_width = w;
	cinfo.image_height = h;
	cinfo.input_components = 3;
	cinfo.in_color_space = JCS_RGB;

	jpeg_set_defaults(&cinfo);
	jpeg_set_quality(&cinfo, quality, TRUE);

	JpegSetDstManager (&cinfo, dst, w * h * (m_localformat.bitsPerPixel / 8));

	jpeg_start_compress(&cinfo, TRUE);

	for (int dy = 0; dy < h; dy++) {
		PrepareRowForJpeg(srcBuf, dy, w);
		jpeg_write_scanlines(&cinfo, rowPointer, 1);
		if (jpegError)
			break;
	}

	if (!jpegError)
		jpeg_finish_compress(&cinfo);

	jpeg_destroy_compress(&cinfo);
	delete[] srcBuf;

	if (jpegError)
		return SendFullColorRect(dst, w, h);

	m_hdrBuffer[m_hdrBufferBytes++] = rfbTightJpeg << 4;

	return SendCompressedData(jpegDstDataLen);
}

void
vncEncodeTight::PrepareRowForJpeg(BYTE *dst, int y, int w)
{
	if (m_remoteformat.bitsPerPixel == 32) {
		CARD32 *src = (CARD32 *)&m_buffer[y * w * sizeof(CARD32)];
		if (m_usePixelFormat24) {
			PrepareRowForJpeg24(dst, src, w);
		} else {
			PrepareRowForJpeg32(dst, src, w);
		}
	} else {
		// 16 bpp assumed.
		CARD16 *src = (CARD16 *)&m_buffer[y * w * sizeof(CARD16)];
		PrepareRowForJpeg16(dst, src, w);
	}
}

void
vncEncodeTight::PrepareRowForJpeg24(BYTE *dst, CARD32 *src, int count)
{
	int r_shift, g_shift, b_shift;
	if (!m_localformat.bigEndian == !m_remoteformat.bigEndian) {
		r_shift = m_remoteformat.redShift;
		g_shift = m_remoteformat.greenShift;
		b_shift = m_remoteformat.blueShift;
	} else {
		r_shift = 24 - m_remoteformat.redShift;
		g_shift = 24 - m_remoteformat.greenShift;
		b_shift = 24 - m_remoteformat.blueShift;
	}

	CARD32 pix;
	while (count--) {
		pix = *src++;
		*dst++ = (BYTE)(pix >> r_shift);
		*dst++ = (BYTE)(pix >> g_shift);
		*dst++ = (BYTE)(pix >> b_shift);
	}
}

#define DEFINE_JPEG_GET_ROW_FUNCTION(bpp)									\
																			\
void																		\
vncEncodeTight::PrepareRowForJpeg##bpp(BYTE *dst, CARD##bpp *src, int count)\
{																			\
	bool endianMismatch =													\
		(!m_localformat.bigEndian != !m_remoteformat.bigEndian);			\
																			\
	int r_shift = m_remoteformat.redShift;									\
	int g_shift = m_remoteformat.greenShift;								\
	int b_shift = m_remoteformat.blueShift; 								\
	int r_max = m_remoteformat.redMax;										\
	int g_max = m_remoteformat.greenMax;									\
	int b_max = m_remoteformat.blueMax; 									\
																			\
	CARD##bpp pix;															\
	while (count--) {														\
		pix = *src++;														\
		if (endianMismatch) {												\
			pix = Swap##bpp(pix);											\
		}																	\
		*dst++ = (BYTE)((pix >> r_shift & r_max) * 255 / r_max);			\
		*dst++ = (BYTE)((pix >> g_shift & g_max) * 255 / g_max);			\
		*dst++ = (BYTE)((pix >> b_shift & b_max) * 255 / b_max);			\
	}																		\
}

DEFINE_JPEG_GET_ROW_FUNCTION(16)
DEFINE_JPEG_GET_ROW_FUNCTION(32)

/*
 * Destination manager implementation for JPEG library.
 */

static struct jpeg_destination_mgr jpegDstManager;
static JOCTET *jpegDstBuffer;
static size_t jpegDstBufferLen;

static void JpegInitDestination(j_compress_ptr cinfo);
static boolean JpegEmptyOutputBuffer(j_compress_ptr cinfo);
static void JpegTermDestination(j_compress_ptr cinfo);

static void
JpegInitDestination(j_compress_ptr cinfo)
{
	jpegError = false;
	jpegDstManager.next_output_byte = jpegDstBuffer;
	jpegDstManager.free_in_buffer = jpegDstBufferLen;
}

static boolean
JpegEmptyOutputBuffer(j_compress_ptr cinfo)
{
	jpegError = true;
	jpegDstManager.next_output_byte = jpegDstBuffer;
	jpegDstManager.free_in_buffer = jpegDstBufferLen;

	return TRUE;
}

static void
JpegTermDestination(j_compress_ptr cinfo)
{
	jpegDstDataLen = jpegDstBufferLen - jpegDstManager.free_in_buffer;
}

static void
JpegSetDstManager(j_compress_ptr cinfo, JOCTET *buf, size_t buflen)
{
	jpegDstBuffer = buf;
	jpegDstBufferLen = buflen;
	jpegDstManager.init_destination = JpegInitDestination;
	jpegDstManager.empty_output_buffer = JpegEmptyOutputBuffer;
	jpegDstManager.term_destination = JpegTermDestination;
	cinfo->dest = &jpegDstManager;
}

