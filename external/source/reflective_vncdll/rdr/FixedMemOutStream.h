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
// A FixedMemOutStream writes to a buffer of a fixed length.
//

#ifndef __RDR_FIXEDMEMOUTSTREAM_H__
#define __RDR_FIXEDMEMOUTSTREAM_H__

#include <rdr/OutStream.h>
#include <rdr/Exception.h>

namespace rdr {

  class FixedMemOutStream : public OutStream {

  public:

    FixedMemOutStream(void* buf, int len) {
      ptr = start = (U8*)buf;
      end = start + len;
    }

    int length() { return ptr - start; }
    void reposition(int pos) { ptr = start + pos; }
    const void* data() { return (const void*)start; }

  private:

    int overrun(int itemSize, int nItems) { throw EndOfStream(); }
    U8* start;
  };

}

#endif
