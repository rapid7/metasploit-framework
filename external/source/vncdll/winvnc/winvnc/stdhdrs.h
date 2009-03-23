//  Copyright (C) 2002-2003 RealVNC Ltd. All Rights Reserved.
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

#define WIN32_LEAN_AND_MEAN
#define STRICT

#include <windows.h>
#include <shellapi.h>
#include <winsock2.h>

#include <malloc.h>
#include <stdio.h>
#include <process.h>
#include <crtdbg.h>

// LOGGING SUPPORT

#include "vnclog.h"
extern VNCLog vnclog;

// No logging at all
#define LL_NONE		0
// Log server startup/shutdown
#define LL_STATE	0
// Log connect/disconnect
#define LL_CLIENTS	1
// Log connection errors (wrong pixfmt, etc)
#define LL_CONNERR	0
// Log socket errors
#define LL_SOCKERR	4
// Log internal errors
#define LL_INTERR	0

// Log internal warnings
#define LL_INTWARN	8
// Log internal info
#define LL_INTINFO	9
// Log socket errors
#define LL_SOCKINFO	10
// Log everything, including internal table setup, etc.
#define LL_ALL		10

// Macros for sticking in the current file name
#define VNCLOG(s)	(__FILE__ " : " s)
