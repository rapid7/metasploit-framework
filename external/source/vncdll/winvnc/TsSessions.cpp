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

#include "TsSessions.h"
#include "DynamicFn.h"
#include <tchar.h>

#ifdef ERROR_CTX_WINSTATION_BUSY
#define RFB_HAVE_WINSTATION_CONNECT
#else
#pragma message("  NOTE: Not building WinStationConnect support.")
#endif

// Windows XP (and later) functions used to handle session Ids
typedef BOOLEAN (WINAPI *_WinStationConnect_proto) (HANDLE,ULONG,ULONG,PCWSTR,ULONG);
DynamicFn<_WinStationConnect_proto> _WinStationConnect(_T("winsta.dll"), "WinStationConnectW");
typedef DWORD (WINAPI *_WTSGetActiveConsoleSessionId_proto) ();
DynamicFn<_WTSGetActiveConsoleSessionId_proto> _WTSGetActiveConsoleSessionId(_T("kernel32.dll"), "WTSGetActiveConsoleSessionId");
typedef BOOL (WINAPI *_ProcessIdToSessionId_proto) (DWORD, DWORD*);
DynamicFn<_ProcessIdToSessionId_proto> _ProcessIdToSessionId(_T("kernel32.dll"), "ProcessIdToSessionId");
typedef BOOL (WINAPI *_LockWorkStation_proto)();
DynamicFn<_LockWorkStation_proto> _LockWorkStation(_T("user32.dll"), "LockWorkStation");


ProcessSessionId::ProcessSessionId(DWORD processId) {
  id = 0;
  if (!_ProcessIdToSessionId.isValid())
    return;
  if (processId == -1)
    processId = GetCurrentProcessId();
  (*_ProcessIdToSessionId)(GetCurrentProcessId(), &id);
}

ProcessSessionId mySessionId;

ConsoleSessionId::ConsoleSessionId() {
  if (_WTSGetActiveConsoleSessionId.isValid())
    id = (*_WTSGetActiveConsoleSessionId)();
  else
    id = 0;
}

bool inConsoleSession() {
  ConsoleSessionId console;
  return console.id == mySessionId.id;
}

void setConsoleSession(DWORD sessionId) {
#ifdef RFB_HAVE_WINSTATION_CONNECT
  if (!_WinStationConnect.isValid()) {
    return;
  }
  if (sessionId == -1)
    sessionId = mySessionId.id;

  // Try to reconnect our session to the console
  ConsoleSessionId console;
  if (!(*_WinStationConnect)(0, sessionId, console.id, L"", 0)) {
    return;
  }

  // Lock the newly connected session, for security
  if (_LockWorkStation.isValid())
    (*_LockWorkStation)();
#else

#endif
}
