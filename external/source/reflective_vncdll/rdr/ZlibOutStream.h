//
// Copyright (C) 2002 RealVNC Ltd.  All Rights Reserved.
//
// This is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This software is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this software; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
// USA.

//
// ZlibOutStream streams to a compressed data stream (underlying), compressing
// with zlib on the fly.
//

#ifndef __RDR_ZLIBOUTSTREAM_H__
#define __RDR_ZLIBOUTSTREAM_H__

#include <rdr/OutStream.h>

struct z_stream_s;

namespace rdr {

  class ZlibOutStream : public OutStream {

  public:

    ZlibOutStream(OutStream* os=0, int bufSize=0);
    virtual ~ZlibOutStream();

    void setUnderlying(OutStream* os);
    void flush();
    int length();

  private:

    int overrun(int itemSize, int nItems);

    OutStream* underlying;
    int bufSize;
    int offset;
    z_stream_s* zs;
    U8* start;
  };

} // end of namespace rdr

#endif
