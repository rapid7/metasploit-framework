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
// TightVNC distribution homepage on the Web: http://www.tightvnc.com/
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
#ifdef HORIZONLIVE
const char mutexname [] = "AppShareHost_Instance_Mutex";
#else
const char mutexname [] = "WinVNC_Win32_Instance_Mutex";
#endif
// The class methods

vncInstHandler::vncInstHandler() : m_mutex(NULL)
{
}

vncInstHandler::~vncInstHandler()
{
	// make sure mutex is cleared as we exit
	Release();
}

BOOL
vncInstHandler::Init()
{
	// Create the named mutex
	m_mutex = CreateMutex(NULL, FALSE, mutexname);
	if (m_mutex == NULL)
		return FALSE;

	// Check that the mutex didn't already exist
	if (GetLastError() == ERROR_ALREADY_EXISTS)
		return FALSE;

	return TRUE;
}

//
// allow mutex to be explicitely cleared
//

DWORD
vncInstHandler::Release() 
{
	//
	// CloseHandle() will throw an exception when
	// passed an invalid handle
	//
	try 
	{ 
		CloseHandle(m_mutex);
	}
	catch (...)
	{
		//
		// Release() should be called once from the user code,
		// and a second time by the object's destructor. 
		// the second call will cause an exception.
		// we can just ignore it.
		//
	}

	return GetLastError();
}
