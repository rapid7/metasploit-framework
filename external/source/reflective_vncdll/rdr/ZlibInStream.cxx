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

#include <rdr/ZlibInStream.h>
#include <rdr/Exception.h>
#include <zlib.h>

using namespace rdr;

enum { DEFAULT_BUF_SIZE = 16384 };

ZlibInStream::ZlibInStream(int bufSize_)
  : underlying(0), bufSize(bufSize_ ? bufSize_ : DEFAULT_BUF_SIZE), offset(0),
    bytesIn(0)
{
  zs = new z_stream;
  zs->zalloc    = Z_NULL;
  zs->zfree     = Z_NULL;
  zs->opaque    = Z_NULL;
  zs->next_in   = Z_NULL;
  zs->avail_in  = 0;
  if (inflateInit(zs) != Z_OK) {
    delete zs;
    throw Exception("ZlibInStream: inflateInit failed");
  }
  ptr = end = start = new U8[bufSize];
}

ZlibInStream::~ZlibInStream()
{
  delete [] start;
  inflateEnd(zs);
  delete zs;
}

void ZlibInStream::setUnderlying(InStream* is, int bytesIn_)
{
  underlying = is;
  bytesIn = bytesIn_;
  ptr = end = start;
}

int ZlibInStream::pos()
{
  return offset + ptr - start;
}

void ZlibInStream::reset()
{
  ptr = end = start;
  if (!underlying) return;

  while (bytesIn > 0) {
    decompress();
    end = start; // throw away any data
  }
  underlying = 0;
}

int ZlibInStream::overrun(int itemSize, int nItems)
{
  if (itemSize > bufSize)
    throw Exception("ZlibInStream overrun: max itemSize exceeded");
  if (!underlying)
    throw Exception("ZlibInStream overrun: no underlying stream");

  if (end - ptr != 0)
    memmove(start, ptr, end - ptr);

  offset += ptr - start;
  end -= ptr - start;
  ptr = start;

  while (end - ptr < itemSize) {
    decompress();
  }

  if (itemSize * nItems > end - ptr)
    nItems = (end - ptr) / itemSize;

  return nItems;
}

// decompress() calls the decompressor once.  Note that this won't necessarily
// generate any output data - it may just consume some input data.

void ZlibInStream::decompress()
{
  zs->next_out = (U8*)end;
  zs->avail_out = start + bufSize - end;

  underlying->check(1);
  zs->next_in = (U8*)underlying->getptr();
  zs->avail_in = underlying->getend() - underlying->getptr();
  if ((int)zs->avail_in > bytesIn)
    zs->avail_in = bytesIn;

  int rc = inflate(zs, Z_SYNC_FLUSH);
  if (rc != Z_OK) {
    throw Exception("ZlibInStream: inflate failed");
  }

  bytesIn -= zs->next_in - underlying->getptr();
  end = zs->next_out;
  underlying->setptr(zs->next_in);
}
