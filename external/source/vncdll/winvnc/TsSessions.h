/* Copyright (C) 2002-2005 RealVNC Ltd.  All Rights Reserved.
 * Copyright (C) 2007 Constantin Kaplinsky.  All Rights Reserved.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */

// Windows version-independent Terminal Services Session discovery
// and manipulation API.  This code will eventually be replaced
// by the full TS-compatibility scheme.

#ifndef __RFB_WIN32_TSSESSIONS_H__
#define __RFB_WIN32_TSSESSIONS_H__

#include "stdhdrs.h"

struct SessionId {
  DWORD id;
};

// Session Id for a given process
struct ProcessSessionId : SessionId {
  ProcessSessionId(DWORD processId = -1);
};

// Session Id for current process
extern ProcessSessionId mySessionId;

// Current console Session Id
struct ConsoleSessionId : SessionId {
  ConsoleSessionId();
};

// Check whether the process is in the Console session at present
bool inConsoleSession();

// Make the specified session the Console session.
//   If sessionId is -1 then the process' session is
//   made the Console session.
void setConsoleSession(DWORD sessionId = -1);

#endif
