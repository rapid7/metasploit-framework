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

#ifndef _WINVNC_ENCODEZRLE
#define _WINVNC_ENCODEZRLE

#include "vncEncoder.h"

namespace rdr { class ZlibOutStream; class MemOutStream; }

class vncEncodeZRLE : public vncEncoder
{
public:
  vncEncodeZRLE();
  ~vncEncodeZRLE();

  virtual void Init();

  virtual UINT RequiredBuffSize(UINT width, UINT height);

  virtual UINT EncodeRect(BYTE *source, BYTE *dest, const rfb::Rect &rect);

private:
  rdr::ZlibOutStream* zos;
  rdr::MemOutStream* mos;
  void* beforeBuf;
};

#endif
