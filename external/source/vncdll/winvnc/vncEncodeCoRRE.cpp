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


// vncEncodeCoRRE

// This file implements the vncEncoder-derived vncEncodeCoRRE class.
// This class overrides some vncEncoder functions to produce a
// Compact RRE encoder.  Compact RRE (CoRRE) uses fewer bytes to
// encode each subrect, which makes it faster in general.  It also
// splits large rectangles up into ones of at most 256 pixels width
// & height.  This results in better granularity to use for deciding
// whether to send RAW or CoRRE/RRE. 

#include "vncEncodeCoRRE.h"
#include "rfb.h"
#include "MinMax.h"
#include <stdlib.h>
#include <time.h>

vncEncodeCoRRE::vncEncodeCoRRE()
{
	m_buffer = NULL;
	m_bufflen = 0;

	// Set some sensible defaults
	m_maxwidth = 24;
	m_maxheight = 24;
	m_maxadjust = 1;

	// Set the threshold up/down probability
	m_threshold = 50;

	// Seed the random number generator
	srand((unsigned)time(NULL));

	m_statsready = FALSE;
	m_encodedbytes = 0;
	m_rectbytes = 0;
}

vncEncodeCoRRE::~vncEncodeCoRRE()
{
	if (m_buffer != NULL)
	{
		delete [] m_buffer;
		m_buffer = NULL;
	}
}

void vncEncodeCoRRE::Init()
{
	vncEncoder::Init();
}

UINT vncEncodeCoRRE::RequiredBuffSize(UINT width, UINT height)
{
	RECT fullscreen;
	UINT codedrects;

	// Work out how many rectangles the entire screen would
	// be re-encoded to...
	fullscreen.left = 0;
	fullscreen.top = 0;
	fullscreen.right = width;
	fullscreen.bottom = height;
	codedrects = NumCodedRects(fullscreen);

	// The buffer size required is the size of raw data for the whole
	// screen plus enough space for the required number of rectangle
	// headers.
	// This is inherently always greater than the RAW encoded size of
	// the whole screen!
	return (codedrects * sz_rfbFramebufferUpdateRectHeader) +
			(width * height * m_remoteformat.bitsPerPixel)/8;
}

UINT
vncEncodeCoRRE::NumCodedRects(RECT &rect)
{
	// If we have any statistical data handy then adjust the CoRRE sizes
	if (m_statsready)
	{
		m_statsready = FALSE;

		UINT newscore = m_encodedbytes * m_lastrectbytes;
		UINT oldscore = m_lastencodedbytes * m_rectbytes;

		if (newscore <= oldscore)
		{
			// The change was a good one, so adjust the threshold accordingly!
			m_threshold = Max(5, Min(95, m_threshold + m_maxadjust));

			m_maxwidth = Max(8, Min(255, m_maxwidth + m_maxadjust));
			m_maxheight = Max(8, Min(255, m_maxheight + m_maxadjust));
		}
		else
		{
			// The change was a bad one, so adjust the threshold accordingly!
			// m_threshold = Max(5, Min(95, m_threshold - m_maxadjust));
		}

		// Now calculate a new adjustment and apply it
		m_maxadjust = ((rand() % 99)<m_threshold) ? 1 : -1;
		
		// Prepare the stats data for next time...
		m_lastencodedbytes = m_encodedbytes;
		m_lastrectbytes = m_rectbytes;

		m_encodedbytes = 0;
		m_rectbytes = 0;
	}

	// Now return the number of rects that this one would encode to
    if ((rect.bottom-rect.top) > m_maxheight)
	{
		RECT subrect1, subrect2;

		// Find how many rects the two subrects would take
		subrect1.left = rect.left;
		subrect1.right = rect.right;
		subrect1.top = rect.top;
		subrect1.bottom = rect.top + m_maxheight;

		subrect2.left = rect.left;
		subrect2.right = rect.right;
		subrect2.top = rect.top + m_maxheight;
		subrect2.bottom = rect.bottom;

		return NumCodedRects(subrect1) + NumCodedRects(subrect2);
	}

    if ((rect.right-rect.left) > m_maxwidth)
	{
		RECT subrect1, subrect2;

		// Find how many rects the two subrects would take
		subrect1.left = rect.left;
		subrect1.right = rect.left + m_maxwidth;
		subrect1.top = rect.top;
		subrect1.bottom = rect.bottom;

		subrect2.left = rect.left + m_maxwidth;
		subrect2.right = rect.right;
		subrect2.top = rect.top;
		subrect2.bottom = rect.bottom;
		return NumCodedRects(subrect1) + NumCodedRects(subrect2);
	}

	// This rectangle is small enough not to require splitting
	return 1;
}

/*
 * corre.c
 *
 * Routines to implement Compact Rise-and-Run-length Encoding (CoRRE).  This
 * code is based on krw's original javatel rfbserver.
 */

/*
 * This version modified for WinVNC by jnw.
 */

static int rreAfterBufLen;

static int subrectEncode8 (CARD8 *source, CARD8 *dest, int w, int h, int max);
static int subrectEncode16 (CARD16 *source, CARD8 *dest, int w, int h, int max);
static int subrectEncode32 (CARD32 *source, CARD8 *dest, int w, int h, int max);
static CARD32 getBgColour (char *data, int size, int bpp);

/*
 * vncEncodeCoRRE::EncodeRect - send an arbitrary size rectangle using CoRRE
 * encoding.
 */

UINT
vncEncodeCoRRE::EncodeRect(BYTE *source, BYTE *dest, const RECT &rect, int offx, int offy)
{
	// Do the encoding
	UINT size = InternalEncodeRect(source, dest, rect);

	const int rectW = rect.right - rect.left;
	const int rectH = rect.bottom - rect.top;
	offsetx = offx;
	offsety = offy;

	// Will this rectangle have been split for encoding?
	if ((rectW>m_maxwidth) || (rectH>m_maxheight))
	{
		// Yes : Once we return, the stats will be valid!
		m_statsready = TRUE;

		// Update the stats
		m_encodedbytes += size;
		m_rectbytes += sz_rfbFramebufferUpdateRectHeader +
			(rectW*rectH*m_remoteformat.bitsPerPixel/8);
	}

	return size;
}

UINT
vncEncodeCoRRE::InternalEncodeRect(BYTE *source, BYTE *dest, const RECT &rect)
{
	int size = 0;

    if ((rect.bottom-rect.top) > m_maxheight)
	{
		RECT subrect;

		// Rectangle is too high - split it into two subrects to send
		subrect.left = rect.left;
		subrect.right = rect.right;
		subrect.top = rect.top;
		subrect.bottom = rect.top + m_maxheight;
		size += InternalEncodeRect(source, dest + size, subrect);

		subrect.left = rect.left;
		subrect.right = rect.right;
		subrect.top = rect.top + m_maxheight;
		subrect.bottom = rect.bottom;
		size += InternalEncodeRect(source, dest + size, subrect);

		return size;
    }

    if ((rect.right-rect.left) > m_maxwidth)
	{
		RECT subrect;

		// Rectangle is too high - split it into two subrects to send
		subrect.left = rect.left;
		subrect.right = rect.left + m_maxwidth;
		subrect.top = rect.top;
		subrect.bottom = rect.bottom;
		size += InternalEncodeRect(source, dest + size, subrect);

		subrect.left = rect.left + m_maxwidth;
		subrect.right = rect.right;
		subrect.top = rect.top;
		subrect.bottom = rect.bottom;
		size += InternalEncodeRect(source, dest + size, subrect);

		return size;
	}

    return EncodeSmallRect(source, dest, rect);
}

void
vncEncodeCoRRE::SetCoRREMax(BYTE width, BYTE height)
{
	m_maxwidth = width;
	m_maxheight = height;
}

/*
 * EncodeSmallRect - send a small (guaranteed < 256x256)
 * rectangle using CoRRE encoding.
 */

UINT
vncEncodeCoRRE::EncodeSmallRect(BYTE *source, BYTE *dest, const RECT &rect)
{
	int subrects = -1;

	const UINT rectW = rect.right - rect.left;
	const UINT rectH = rect.bottom - rect.top;

	// Create the rectangle header
	rfbFramebufferUpdateRectHeader *surh=(rfbFramebufferUpdateRectHeader *)dest;
	surh->r.x = (CARD16) rect.left;
	surh->r.y = (CARD16) rect.top;
	surh->r.w = (CARD16) (rectW);
	surh->r.h = (CARD16) (rectH);
	surh->r.x = Swap16IfLE(surh->r.x - offsetx);
	surh->r.y = Swap16IfLE(surh->r.y - offsety);
	surh->r.w = Swap16IfLE(surh->r.w);
	surh->r.h = Swap16IfLE(surh->r.h);
	surh->encoding = Swap32IfLE(rfbEncodingCoRRE);

	// create a space big enough for the CoRRE encoded pixels

	size_t rectSize = rectW * rectH * (m_remoteformat.bitsPerPixel / 8);
	if (m_bufflen < rectSize)
	{
		if (m_buffer != NULL)
		{
			delete [] m_buffer;
			m_buffer = NULL;
		}
		m_buffer = new BYTE [rectSize + 1];
		if (m_buffer == NULL)
			return vncEncoder::EncodeRect(source, dest, rect, offsetx, offsety);

		m_bufflen = rectSize;
	}
	
	// Translate the data into our new buffer
	Translate(source, m_buffer, rect);

	// The Buffer object will have ensured that the destination buffer is
	// big enough using RequiredBuffSize

	// Choose the appropriate encoding routine (for speed...)
	switch(m_remoteformat.bitsPerPixel)
	{
	case 8:
		subrects = subrectEncode8(
			m_buffer,
			dest+sz_rfbFramebufferUpdateRectHeader+sz_rfbRREHeader,
			rectW,
			rectH,
			(int)(m_bufflen-sz_rfbFramebufferUpdateRectHeader-sz_rfbRREHeader)
			);
		break;
	case 16:
		subrects = subrectEncode16(
			(CARD16 *)m_buffer,
			(CARD8 *)(dest+sz_rfbFramebufferUpdateRectHeader+sz_rfbRREHeader),
			rectW,
			rectH,
			(int)(m_bufflen-sz_rfbFramebufferUpdateRectHeader-sz_rfbRREHeader)
			);
		break;
	case 32:
		subrects = subrectEncode32(
			(CARD32 *)m_buffer,
			(CARD8 *)(dest+sz_rfbFramebufferUpdateRectHeader+sz_rfbRREHeader),
			rectW,
			rectH,
			(int)(m_bufflen-sz_rfbFramebufferUpdateRectHeader-sz_rfbRREHeader)
			);
		break;
	}

	// If we couldn't encode the rectangles then just send the data raw
	if (subrects < 0)
		return vncEncoder::EncodeRect(source, dest, rect, offsetx, offsety);

	// Send the RREHeader
	rfbRREHeader *rreh=(rfbRREHeader *)(dest+sz_rfbFramebufferUpdateRectHeader);
	rreh->nSubrects = Swap32IfLE(subrects);

	// Update the statistics for this rectangle.
	encodedSize += sz_rfbRREHeader + rreAfterBufLen;
	rectangleOverhead += sz_rfbFramebufferUpdateRectHeader;
	dataSize += ( rectW * rectH * m_remoteformat.bitsPerPixel) / 8;
	transmittedSize += sz_rfbFramebufferUpdateRectHeader + sz_rfbRREHeader + rreAfterBufLen;
	
	// Calculate the size of the buffer produced
	return sz_rfbFramebufferUpdateRectHeader + sz_rfbRREHeader + rreAfterBufLen;
}

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
 */

#define DEFINE_SUBRECT_ENCODE(bpp)							\
static int													\
subrectEncode##bpp(											\
	CARD##bpp *source,										\
    CARD8 *dest,											\
	int w,													\
	int h,													\
	int maxbytes)											\
{															\
    CARD##bpp cl;											\
    rfbCoRRERectangle subrect;								\
    int x,y;												\
    int i,j;												\
    int hx=0,hy,vx=0,vy;									\
    int hyflag;												\
    CARD##bpp *seg;											\
    CARD##bpp *line;										\
    int hw,hh,vw,vh;										\
    int thex,they,thew,theh;								\
    int numsubs = 0;										\
    int newLen;												\
    CARD##bpp bg = (CARD##bpp)getBgColour((char*)source,w*h,bpp);	\
															\
    *((CARD##bpp*)dest) = bg;								\
															\
    rreAfterBufLen = (bpp/8);								\
															\
    for (y=0; y<h; y++) {									\
      line = source+(y*w);									\
      for (x=0; x<w; x++) {									\
        if (line[x] != bg) {								\
          cl = line[x];										\
          hy = y-1;											\
          hyflag = 1;										\
          for (j=y; j<h; j++) {								\
            seg = source+(j*w);								\
            if (seg[x] != cl) {break;}					    \
            i = x;											\
            while ((seg[i] == cl) && (i < w)) i += 1;		\
            i -= 1;											\
            if (j == y) vx = hx = i;					    \
            if (i < vx) vx = i;								\
            if ((hyflag > 0) && (i >= hx)) {hy += 1;} else {hyflag = 0;}      \
          }													\
          vy = j-1;											\
															\
          /*  We now have two possible subrects: (x,y,hx,hy) and (x,y,vx,vy)  \
           *  We'll choose the bigger of the two.			\
           */												\
          hw = hx-x+1;										\
          hh = hy-y+1;										\
          vw = vx-x+1;										\
          vh = vy-y+1;										\
															\
          thex = x;											\
          they = y;											\
															\
          if ((hw*hh) > (vw*vh)) {							\
            thew = hw;										\
            theh = hh;										\
          } else {											\
            thew = vw;										\
            theh = vh;										\
          }													\
															\
          subrect.x = thex;									\
          subrect.y = they;									\
          subrect.w = thew;									\
          subrect.h = theh;									\
															\
	  newLen = rreAfterBufLen + (bpp/8) + sz_rfbCoRRERectangle;			\
          if ((newLen > (w * h * (bpp/8))) || (newLen > maxbytes))		\
	    return -1;											\
															\
	  numsubs += 1;											\
	  *((CARD##bpp*)(dest + rreAfterBufLen)) = cl;			\
	  rreAfterBufLen += (bpp/8);							\
	  memcpy(&dest[rreAfterBufLen],&subrect,sz_rfbCoRRERectangle);		\
	  rreAfterBufLen += sz_rfbCoRRERectangle;			    \
															\
		  /*												\
           * Now mark the subrect as done.				    \
           */												\
          for (j=they; j < (they+theh); j++) {				\
            for (i=thex; i < (thex+thew); i++) {			\
              source[j*w+i] = bg;								\
            }												\
          }													\
        }													\
      }														\
    }														\
															\
    return numsubs;											\
}

DEFINE_SUBRECT_ENCODE(8)
DEFINE_SUBRECT_ENCODE(16)
DEFINE_SUBRECT_ENCODE(32)

/*
 * getBgColour() gets the most prevalent colour in a byte array.
 */
static CARD32
getBgColour(
	char *data,
	int size,
	int bpp)
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
