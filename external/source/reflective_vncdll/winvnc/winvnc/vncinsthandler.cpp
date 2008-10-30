//  Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.
//
//  This file is part of the VNC system.
//
//  The VNC system is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
//  USA.
//
// If the source code for the VNC system is not available from the place 
// whence you received this file, check http://www.uk.research.att.com/vnc or contact
// the authors on vnc@uk.research.att.com for information on obtaining it.


// vncInstHandler.cpp

// Implementation of the class used to ensure that only
// one instance is running

#include "stdhdrs.h"
#include "vncInstHandler.h"

// Name of the mutex

const char mutexname [] = "WinVNC_Win32_Instance_Mutex";

// The class methods

BOOL
vncInstHandler::Init()
{
	// Create the named mutex
	HANDLE mutex = CreateMutex(NULL, FALSE, mutexname);
	if (mutex == NULL)
		return FALSE;

	// Check that the mutex didn't already exist
	if (GetLastError() == ERROR_ALREADY_EXISTS)
		return FALSE;

	return TRUE;
}
