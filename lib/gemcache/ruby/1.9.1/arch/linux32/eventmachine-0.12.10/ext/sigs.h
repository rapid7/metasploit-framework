/*****************************************************************************

$Id$

File:     sigs.h
Date:     06Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/


#ifndef __Signals__H_
#define __Signals__H_

void InstallSignalHandlers();
extern bool gTerminateSignalReceived;

#ifdef OS_WIN32
void HookControlC (bool);
#endif

#endif // __Signals__H_

