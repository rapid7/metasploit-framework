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

#ifndef __RDR_EXCEPTION_H__
#define __RDR_EXCEPTION_H__

#include <stdio.h>
#include <string.h>

namespace rdr {

  struct Exception {
    enum { len = 256 };
    char str_[len];
    Exception(const char* s=0, const char* e="rdr::Exception") {
      str_[0] = 0;
      strncat(str_, e, len-1);
      if (s) {
        strncat(str_, ": ", len-1-strlen(str_));
        strncat(str_, s, len-1-strlen(str_));
      }
    }
    virtual const char* str() const { return str_; }
  };

  struct SystemException : public Exception {
    int err;
    SystemException(const char* s, int err_) : err(err_) {
      str_[0] = 0;
      strncat(str_, "rdr::SystemException: ", len-1);
      strncat(str_, s, len-1-strlen(str_));
      strncat(str_, ": ", len-1-strlen(str_));
      strncat(str_, strerror(err), len-1-strlen(str_));
      strncat(str_, " (", len-1-strlen(str_));
      char buf[20];
      sprintf(buf,"%d",err);
      strncat(str_, buf, len-1-strlen(str_));
      strncat(str_, ")", len-1-strlen(str_));
    }
  }; 

  struct TimedOut : public Exception {
    TimedOut(const char* s=0) : Exception(s,"rdr::TimedOut") {}
  };
 
  struct EndOfStream : public Exception {
    EndOfStream(const char* s=0) : Exception(s,"rdr::EndOfStream") {}
  };

  struct FrameException : public Exception {
    FrameException(const char* s=0) : Exception(s,"rdr::FrameException") {}
  };

}

#endif
