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


// vncEncodeRRE

// This file implements the vncEncoder-derived vncEncodeRRE class.
// This class overrides some vncEncoder functions to produce a bitmap
// to RRE encoder.  RRE is much more efficient than RAW format on
// most screen data.

#include "vncEncodeRRE.h"

vncEncodeRRE::vncEncodeRRE()
{
	m_buffer = NULL;
	m_bufflen = 0;
}

vncEncodeRRE::~vncEncodeRRE()
{
	if (m_buffer != NULL)
	{
		delete [] m_buffer;
		m_buffer = NULL;
	}
}

void
vncEncodeRRE::Init()
{
	vncEncoder::Init();
}

UINT
vncEncodeRRE::RequiredBuffSize(UINT width, UINT height)
{
	return vncEncoder::RequiredBuffSize(width, height);
}

UINT
vncEncodeRRE::NumCodedRects(const rfb::Rect &rect)
{
	return 1;
}

/*****************************************************************************
 *
 * Routines to implement Rise-and-Run-length Encoding (RRE).  This code is
 * based on krw's original javatel rfbserver.
 * This code courtesy of tjr
 */

/*
 * rreBeforeBuf contains pixel data in the client's format.
 * rreAfterBuf contains the RRE encoded version.  If the RRE encoded version is
 * larger than the raw data or if it exceeds rreAfterBufSize then
 * normal encoding is used instead.
 */

static int rreAfterBufLen;

static int subrectEncode8 (CARD8 *data, CARD8 *buf, int w, int h, int maxBytes);
static int subrectEncode16 (CARD16 *data, CARD8 *buf, int w, int h, int maxBytes);
static int subrectEncode32 (CARD32 *data, CARD8 *buf, int w, int h, int maxBytes);
static CARD32 getBgColour (char *data, int size, int bpp);

/*
 * subrectEncode() encodes the given multicoloured rectangle as a background 
 * colour overwritten by single-coloured rectangles.  It returns the number 
 * of subrectangles in the encoded buffer, or -1 if subrect encoding won't
 * fit in the buffer.  It puts the encoded rectangles in rreAfterBuf.  The
 * single-colour rectangle partition is not optimal, but does find the biggest
 * horizontal or vertical rectangle top-left anchored to each consecutive 
 * coordinate position.
 *
 * The coding scheme is simply [<bgcolour><subrect><subrect>...] where each 
 * <subrect> is [<colour><x><y><w><h>].
 *
 * This code has been modified from tjr's original by Wez(jnw)
 */

#define DEFINE_SUBRECT_ENCODE(bpp)											\
static int																	\
subrectEncode##bpp(															\
	CARD##bpp *data,														\
	CARD8 *buf,																\
	int w,																	\
	int h,																	\
	int maxBytes															\
	)																		\
{																			\
    CARD##bpp cl;															\
    rfbRectangle subrect;													\
    int x,y;																\
    int i,j;																\
    int hx,hy,vx,vy;														\
    int hyflag;																\
    CARD##bpp *seg;															\
    CARD##bpp *line;														\
    int hw,hh,vw,vh;														\
    int thex,they,thew,theh;												\
    int numsubs = 0;														\
    int newLen;																\
    CARD##bpp bg = (CARD##bpp)getBgColour((char*)data,w*h,bpp);				\
																			\
	/* Set the background colour value */									\
	*((CARD##bpp *)buf) = bg;																\
																			\
    rreAfterBufLen = (bpp/8);												\
																			\
    for (y=0; y<h; y++) {													\
      line = data+(y*w);													\
      for (x=0; x<w; x++) {													\
        if (line[x] != bg) {												\
          cl = line[x];														\
          hy = y-1;															\
          hyflag = 1;														\
          for (j=y; j<h; j++) {												\
            seg = data+(j*w);												\
            if (seg[x] != cl) {break;}										\
            i = x;															\
            while ((i < w) && (seg[i] == cl)) i += 1;						\
            i -= 1;															\
            if (j == y) vx = hx = i;										\
            if (i < vx) vx = i;												\
            if ((hyflag > 0) && (i >= hx)) {hy += 1;} else {hyflag = 0;}	\
          }																	\
          vy = j-1;															\
																			\
          /*  We now have two possible subrects: (x,y,hx,hy) and (x,y,vx,vy)	\
           *  We'll choose the bigger of the two.								\
           */																\
          hw = hx-x+1;														\
          hh = hy-y+1;														\
          vw = vx-x+1;														\
          vh = vy-y+1;														\
																			\
          thex = x;															\
          they = y;															\
																			\
          if ((hw*hh) > (vw*vh)) {											\
            thew = hw;														\
            theh = hh;														\
          } else {															\
            thew = vw;														\
            theh = vh;														\
          }																	\
																			\
          subrect.x = Swap16IfLE(thex);										\
          subrect.y = Swap16IfLE(they);										\
          subrect.w = Swap16IfLE(thew);										\
          subrect.h = Swap16IfLE(theh);										\
																			\
	newLen = rreAfterBufLen + (bpp/8) + sz_rfbRectangle;					\
	if ((newLen > (w * h * (bpp/8))) || (newLen > maxBytes))				\
	    return -1;															\
																			\
	  numsubs += 1;															\
	  *((CARD##bpp *)(buf + rreAfterBufLen)) = cl;											\
	  rreAfterBufLen += (bpp/8);											\
	  memcpy(&buf[rreAfterBufLen],&subrect, sz_rfbRectangle);				\
	  rreAfterBufLen += sz_rfbRectangle;									\
																			\
          /*																\
           * Now mark the subrect as done.									\
           */																\
          for (j=they; j < (they+theh); j++) {								\
            for (i=thex; i < (thex+thew); i++) {							\
              data[j*w+i] = bg;												\
            }																\
          }																	\
        }																	\
      }																		\
    }																		\
																			\
    return numsubs;															\
}

DEFINE_SUBRECT_ENCODE(8)
DEFINE_SUBRECT_ENCODE(16)
DEFINE_SUBRECT_ENCODE(32)

/*
 * getBgColour() gets the most prevalent colour in a byte array.
 */
static CARD32
getBgColour(char *data, int size, int bpp)
{
    
#define NUMCLRS 256
  
  static int counts[NUMCLRS];
  int i,j,k;

  int maxcount = 0;
  CARD8 maxclr = 0;

  if (bpp != 8) {
    if (bpp == 16) {
      return ((CARD16 *)data)[0];
    } else if (bpp == 32) {
      return ((CARD32 *)data)[0];
    } else {
      fprintf(stderr,"getBgColour: bpp %d?\n",bpp);
      exit(1);
    }
  }

  for (i=0; i<NUMCLRS; i++) {
    counts[i] = 0;
  }

  for (j=0; j<size; j++) {
    k = (int)(((CARD8 *)data)[j]);
    if (k >= NUMCLRS) {
      fprintf(stderr, "%s: unusual colour = %d\n", "getBgColour",k);
      exit(1);
    }
    counts[k] += 1;
    if (counts[k] > maxcount) {
      maxcount = counts[k];
      maxclr = ((CARD8 *)data)[j];
    }
  }
  
  return maxclr;
}

// Encode the rectangle using RRE
inline UINT
vncEncodeRRE::EncodeRect(BYTE *source, BYTE *dest, const rfb::Rect &rect)
{
	int subrects = -1;

	const UINT rectW = rect.br.x - rect.tl.x;
	const UINT rectH = rect.br.y - rect.tl.y;

	// Create the rectangle header
	rfbFramebufferUpdateRectHeader *surh=(rfbFramebufferUpdateRectHeader *)dest;
	surh->r.x = (CARD16) rect.tl.x;
	surh->r.y = (CARD16) rect.tl.y;
	surh->r.w = (CARD16) (rectW);
	surh->r.h = (CARD16) (rectH);
	surh->r.x = Swap16IfLE(surh->r.x);
	surh->r.y = Swap16IfLE(surh->r.y);
	surh->r.w = Swap16IfLE(surh->r.w);
	surh->r.h = Swap16IfLE(surh->r.h);
	surh->encoding = Swap32IfLE(rfbEncodingRRE);
	
	// create a space big enough for the RRE encoded pixels
	if (m_bufflen < (rectW*rectH*m_remoteformat.bitsPerPixel / 8))
	{
		if (m_buffer != NULL)
		{
			delete [] m_buffer;
			m_buffer = NULL;
		}
		m_buffer = new BYTE [rectW*rectH*m_remoteformat.bitsPerPixel/8+1];
		if (m_buffer == NULL)
			return vncEncoder::EncodeRect(source, dest, rect);
		m_bufflen = rectW*rectH*m_remoteformat.bitsPerPixel/8;
	}
	
	// Translate the data into our new buffer
	Translate(source, m_buffer, rect);

	// Choose the appropriate encoding routine (for speed...)
	switch(m_remoteformat.bitsPerPixel)
	{
	case 8:
		subrects = subrectEncode8(
			m_buffer,
			dest+sz_rfbFramebufferUpdateRectHeader+sz_rfbRREHeader,
			rectW,
			rectH,
			m_bufflen-sz_rfbFramebufferUpdateRectHeader-sz_rfbRREHeader
			);
		break;
	case 16:
		subrects = subrectEncode16(
			(CARD16 *)m_buffer,
			(CARD8 *)(dest+sz_rfbFramebufferUpdateRectHeader+sz_rfbRREHeader),
			rectW,
			rectH,
			m_bufflen-sz_rfbFramebufferUpdateRectHeader-sz_rfbRREHeader
			);
		break;
	case 32:
		subrects = subrectEncode32(
			(CARD32 *)m_buffer,
			(CARD8 *)(dest+sz_rfbFramebufferUpdateRectHeader+sz_rfbRREHeader),
			rectW,
			rectH,
			m_bufflen-sz_rfbFramebufferUpdateRectHeader-sz_rfbRREHeader
			);
		break;
	}

	// If we couldn't encode the rectangles then just send the data raw
	if (subrects < 0)
		return vncEncoder::EncodeRect(source, dest, rect);

	// Send the RREHeader
	rfbRREHeader *rreh=(rfbRREHeader *)(dest+sz_rfbFramebufferUpdateRectHeader);
	rreh->nSubrects = Swap32IfLE(subrects);
	
	// Return the amount of data sent	
	return sz_rfbFramebufferUpdateRectHeader + sz_rfbRREHeader +
		(m_remoteformat.bitsPerPixel / 8) +
		(subrects * (sz_rfbRectangle + m_remoteformat.bitsPerPixel / 8));
}
