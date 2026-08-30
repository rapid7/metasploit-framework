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


// vncEncodeTight object

class vncEncodeTight;

#if !defined(_WINVNC_ENCODETIGHT)
#define _WINVNC_ENCODETIGHT
#pragma once

#include "vncEncoder.h"

#include "zlib/zlib.h"
extern "C" {
#include "libjpeg/jpeglib.h"
}

// Minimum amount of data to be compressed. This value should not be
// changed, doing so will break compatibility with existing clients.
#define TIGHT_MIN_TO_COMPRESS 12

// The parameters below may be adjusted.
#define MIN_SPLIT_RECT_SIZE     4096
#define MIN_SOLID_SUBRECT_SIZE  2048
#define MAX_SPLIT_TILE_SIZE       16

// C-style structures to store palette entries and compression paramentes.
// Such code probably should be converted into C++ classes.

struct COLOR_LIST {
	COLOR_LIST *next;
	int idx;
	CARD32 rgb;
};

struct PALETTE_ENTRY {
	COLOR_LIST *listNode;
	int numPixels;
};

struct PALETTE {
	PALETTE_ENTRY entry[256];
	COLOR_LIST *hash[256];
	COLOR_LIST list[256];
};

struct TIGHT_CONF {
	int maxRectSize, maxRectWidth;
	int monoMinRectSize, gradientMinRectSize;
	int idxZlibLevel, monoZlibLevel, rawZlibLevel, gradientZlibLevel;
	unsigned long gradientThreshold, gradientThreshold24;
	int idxMaxColorsDivisor;
	int jpegQuality;
	unsigned long jpegThreshold, jpegThreshold24;
};


// Class definition

class vncEncodeTight : public vncEncoder
{
// Fields
public:

// Methods
public:
	// Create/Destroy methods
	vncEncodeTight();
	~vncEncodeTight();

	//virtual VOID UpdateZLibDictionary( AGENT_CTX * lpAgentContext );
	//virtual VOID DumpZLibDictionary( AGENT_CTX * lpAgentContext );

	virtual void Init();
	virtual const char* GetEncodingName() { return "Tight"; }

	virtual UINT RequiredBuffSize(UINT width, UINT height);
	virtual UINT NumCodedRects(RECT &rect);

	virtual UINT EncodeRect(BYTE *source, VSocket *outConn, BYTE *dest, const RECT &rect, int offx, int offy);

// Implementation
protected:
	int m_paletteNumColors, m_paletteMaxColors;
	CARD32 m_monoBackground, m_monoForeground;
	PALETTE m_palette;

	z_stream m_zsStruct[4];
	bool m_zsActive[4];
	int m_zsLevel[4];

	BYTE *m_hdrBuffer;
	int m_hdrBufferBytes;
	BYTE *m_buffer;
	int m_bufflen;
	int *m_prevRowBuf;
	int	offsetx;
	int	offsety;

	bool m_usePixelFormat24;

	static const TIGHT_CONF m_conf[10];

	// Protected member functions.

	void FindBestSolidArea(BYTE *source, int x, int y, int w, int h,
						   CARD32 colorValue, int *w_ptr, int *h_ptr);
	void ExtendSolidArea  (BYTE *source, int x, int y, int w, int h,
						   CARD32 colorValue,
						   int *x_ptr, int *y_ptr, int *w_ptr, int *h_ptr);
	bool CheckSolidTile   (BYTE *source, int x, int y, int w, int h,
						   CARD32 *colorPtr, bool needSameColor);
	bool CheckSolidTile8  (BYTE *source, int x, int y, int w, int h,
						   CARD32 *colorPtr, bool needSameColor);
	bool CheckSolidTile16 (BYTE *source, int x, int y, int w, int h,
						   CARD32 *colorPtr, bool needSameColor);
	bool CheckSolidTile32 (BYTE *source, int x, int y, int w, int h,
						   CARD32 *colorPtr, bool needSameColor);

	UINT EncodeRectSimple (BYTE *source, VSocket *outConn, BYTE *dest,
						   const RECT &rect);
	UINT EncodeSubrect    (BYTE *source, VSocket *outConn, BYTE *dest,
						   int x, int y, int w, int h);
	void SendTightHeader  (int x, int y, int w, int h);

	int SendSolidRect     (BYTE *dest);
	int SendMonoRect      (BYTE *dest, int w, int h);
	int SendIndexedRect   (BYTE *dest, int w, int h);
	int SendFullColorRect (BYTE *dest, int w, int h);
	int SendGradientRect  (BYTE *dest, int w, int h);
	int CompressData      (BYTE *dest, int streamId, int dataLen,
						   int zlibLevel, int zlibStrategy);
	int SendCompressedData(size_t compressedLen);

	void FillPalette8 (int count);
	void FillPalette16(int count);
	void FillPalette32(int count);

	void PaletteReset(void);
	int PaletteInsert(CARD32 rgb, int numPixels, int bpp);

	void Pack24(BYTE *buf, int count);

	void EncodeIndexedRect16(BYTE *buf, int count);
	void EncodeIndexedRect32(BYTE *buf, int count);

	void EncodeMonoRect8 (BYTE *buf, int w, int h);
	void EncodeMonoRect16(BYTE *buf, int w, int h);
	void EncodeMonoRect32(BYTE *buf, int w, int h);

	void FilterGradient24(BYTE *buf, int w, int h);
	void FilterGradient16(CARD16 *buf, int w, int h);
	void FilterGradient32(CARD32 *buf, int w, int h);

	int DetectSmoothImage (int w, int h);
	unsigned long DetectSmoothImage24 (int w, int h);
	unsigned long DetectSmoothImage16 (int w, int h);
	unsigned long DetectSmoothImage32 (int w, int h);

	int SendJpegRect(BYTE *dst, int w, int h, int quality);
	void PrepareRowForJpeg(BYTE *dst, int y, int w);
	void PrepareRowForJpeg24(BYTE *dst, CARD32 *src, int count);
	void PrepareRowForJpeg16(BYTE *dst, CARD16 *src, int count);
	void PrepareRowForJpeg32(BYTE *dst, CARD32 *src, int count);
};

#endif // _WINVNC_ENCODETIGHT

