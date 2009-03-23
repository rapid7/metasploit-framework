//  Copyright (C) 2002-2003 RealVNC Ltd. All Rights Reserved.
//
//  This program is free software; you can redistribute it and/or modify
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
// If the source code for the program is not available from the place from
// which you received this file, check http://www.realvnc.com/ or contact
// the authors on info@realvnc.com for information on obtaining it.

#include "vncEncodeZRLE.h"
#include "rfb.h"
#include "rfbMisc.h"
#include <stdlib.h>
#include <time.h>
#include <rdr/MemOutStream.h>
#include <rdr/ZlibOutStream.h>
#include <rdr/Exception.h>

#define GET_IMAGE_INTO_BUF(tx,ty,tw,th,buf)     \
  rfb::Rect rect;                                    \
  rect.tl.x = tx;                               \
  rect.tl.y = ty;                                \
  rect.br.x = tx+tw;                           \
  rect.br.y = ty+th;                          \
  encoder->Translate(source, (BYTE*)buf, rect);

#define EXTRA_ARGS , BYTE* source, vncEncoder* encoder

#define BPP 8
#include <rfb/zrleEncode.h>
#undef BPP
#define BPP 16
#include <rfb/zrleEncode.h>
#undef BPP
#define BPP 32
#include <rfb/zrleEncode.h>
#define CPIXEL 24A
#include <rfb/zrleEncode.h>
#undef CPIXEL
#define CPIXEL 24B
#include <rfb/zrleEncode.h>
#undef CPIXEL
#undef BPP

vncEncodeZRLE::vncEncodeZRLE()
{
  mos = new rdr::MemOutStream;
  zos = new rdr::ZlibOutStream;
  beforeBuf = new rdr::U32[rfbZRLETileWidth * rfbZRLETileHeight + 1];
}

vncEncodeZRLE::~vncEncodeZRLE()
{
  delete mos;
  delete zos;
  delete [] beforeBuf;
}

void vncEncodeZRLE::Init()
{
  vncEncoder::Init();
}

UINT vncEncodeZRLE::RequiredBuffSize(UINT width, UINT height)
{
  // this is a guess - 12 bytes plus 1.5 times raw... (zlib.h says compress
  // needs 12 bytes plus 1.001 times raw data but that's not quite what we give
  // zlib anyway)
  return (sz_rfbFramebufferUpdateRectHeader + sz_rfbZRLEHeader + 12 +
          width * height * (m_remoteformat.bitsPerPixel / 8) * 3 / 2);
}

UINT vncEncodeZRLE::EncodeRect(BYTE *source, BYTE *dest, const rfb::Rect &rect)
{
  int x = rect.tl.x;
  int y = rect.tl.y;
  int w = rect.br.x - x;
  int h = rect.br.y - y;

  try {
    mos->clear();

    switch (m_remoteformat.bitsPerPixel) {

    case 8:
      zrleEncode8( x, y, w, h, mos, zos, beforeBuf, source, this);
      break;

    case 16:
      zrleEncode16(x, y, w, h, mos, zos, beforeBuf, source, this);
      break;

    case 32:
      bool fitsInLS3Bytes
        = ((m_remoteformat.redMax   << m_remoteformat.redShift)   < (1<<24) &&
           (m_remoteformat.greenMax << m_remoteformat.greenShift) < (1<<24) &&
           (m_remoteformat.blueMax  << m_remoteformat.blueShift)  < (1<<24));

      bool fitsInMS3Bytes = (m_remoteformat.redShift   > 7  &&
                             m_remoteformat.greenShift > 7  &&
                             m_remoteformat.blueShift  > 7);

      if ((fitsInLS3Bytes && !m_remoteformat.bigEndian) ||
          (fitsInMS3Bytes && m_remoteformat.bigEndian))
      {
        zrleEncode24A(x, y, w, h, mos, zos, beforeBuf, source, this);
      }
      else if ((fitsInLS3Bytes && m_remoteformat.bigEndian) ||
               (fitsInMS3Bytes && !m_remoteformat.bigEndian))
      {
        zrleEncode24B(x, y, w, h, mos, zos, beforeBuf, source, this);
      }
      else
      {
        zrleEncode32(x, y, w, h, mos, zos, beforeBuf, source, this);
      }
      break;
    }

    rfbFramebufferUpdateRectHeader* surh = (rfbFramebufferUpdateRectHeader*)dest;
    surh->r.x = Swap16IfLE(x);
    surh->r.y = Swap16IfLE(y);
    surh->r.w = Swap16IfLE(w);
    surh->r.h = Swap16IfLE(h);
    surh->encoding = Swap32IfLE(rfbEncodingZRLE);

    rfbZRLEHeader* hdr = (rfbZRLEHeader*)(dest +
                                          sz_rfbFramebufferUpdateRectHeader);

    hdr->length = Swap32IfLE(mos->length());

    memcpy(dest + sz_rfbFramebufferUpdateRectHeader + sz_rfbZRLEHeader,
           (rdr::U8*)mos->data(), mos->length());

    return sz_rfbFramebufferUpdateRectHeader + sz_rfbZRLEHeader + mos->length();
  } catch (rdr::Exception& e) {
    //vnclog.Print(LL_INTERR, VNCLOG("ZRLE EncodeRect error:%s\n"), e.str());
    return 0;
  }
}
