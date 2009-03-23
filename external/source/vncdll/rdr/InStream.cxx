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

#include <rdr/InStream.h>
#include <rdr/Exception.h>

using namespace rdr;

U32 InStream::maxStringLength = 65535;

char* InStream::readString()
{
  U32 len = readU32();
  if (len > maxStringLength)
    throw Exception("InStream max string length exceeded");
  char* str = new char[len+1];
  readBytes(str, len);
  str[len] = 0;
  return str;
}
