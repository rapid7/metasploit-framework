/*****************************************************************************

$Id$

File:     sigs.cpp
Date:     06Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/

#include "project.h"


bool gTerminateSignalReceived;


/**************
SigtermHandler
**************/

void SigtermHandler (int sig)
{
	// This is a signal-handler, don't do anything frisky. Interrupts are disabled.
	// Set the terminate flag WITHOUT trying to lock a mutex- otherwise we can easily
	// self-deadlock, especially if the event machine is looping quickly.
	gTerminateSignalReceived = true;
}


/*********************
InstallSignalHandlers
*********************/

void InstallSignalHandlers()
{
	#ifdef OS_UNIX
	static bool bInstalled = false;
	if (!bInstalled) {
		bInstalled = true;
		signal (SIGINT, SigtermHandler);
		signal (SIGTERM, SigtermHandler);
		signal (SIGPIPE, SIG_IGN);
	}
	#endif
}



/*******************
WintelSignalHandler
*******************/

#ifdef OS_WIN32
BOOL WINAPI WintelSignalHandler (DWORD control)
{
	if (control == CTRL_C_EVENT)
		gTerminateSignalReceived = true;
	return TRUE;
}
#endif

/************
HookControlC
************/

#ifdef OS_WIN32
void HookControlC (bool hook)
{
	if (hook) {
		// INSTALL hook
		SetConsoleCtrlHandler (WintelSignalHandler, TRUE);
	}
	else {
		// UNINSTALL hook
		SetConsoleCtrlHandler (WintelSignalHandler, FALSE);
	}
}
#endif


