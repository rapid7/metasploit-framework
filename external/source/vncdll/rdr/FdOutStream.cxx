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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#ifdef _WIN32
#include <winsock.h>
#define write(s,b,l) send(s,(const char*)b,l,0)
#undef errno
#define errno WSAGetLastError()
#else
#include <unistd.h>
#include <sys/time.h>
#endif

#include <rdr/FdOutStream.h>
#include <rdr/Exception.h>


using namespace rdr;

enum { DEFAULT_BUF_SIZE = 16384,
       MIN_BULK_SIZE = 1024 };

FdOutStream::FdOutStream(int fd_, int bufSize_)
  : fd(fd_), bufSize(bufSize_ ? bufSize_ : DEFAULT_BUF_SIZE), offset(0)
{
  ptr = start = new U8[bufSize];
  end = start + bufSize;
}

FdOutStream::~FdOutStream()
{
  try {
    flush();
  } catch (Exception&) {
  }
  delete [] start;
}


void FdOutStream::writeBytes(const void* data, int length)
{
  if (length < MIN_BULK_SIZE) {
    OutStream::writeBytes(data, length);
    return;
  }

  const U8* dataPtr = (const U8*)data;

  flush();

  while (length > 0) {
    int n = write(fd, dataPtr, length);

    if (n < 0) throw SystemException("write",errno);

    length -= n;
    dataPtr += n;
    offset += n;
  }
}

int FdOutStream::length()
{
  return offset + ptr - start;
}

void FdOutStream::flush()
{
  U8* sentUpTo = start;
  while (sentUpTo < ptr) {
    int n = write(fd, (const void*) sentUpTo, ptr - sentUpTo);

    if (n < 0) throw SystemException("write",errno);

    sentUpTo += n;
    offset += n;
  }

  ptr = start;
}


int FdOutStream::overrun(int itemSize, int nItems)
{
  if (itemSize > bufSize)
    throw Exception("FdOutStream overrun: max itemSize exceeded");

  flush();

  if (itemSize * nItems > end - ptr)
    nItems = (end - ptr) / itemSize;

  return nItems;
}
