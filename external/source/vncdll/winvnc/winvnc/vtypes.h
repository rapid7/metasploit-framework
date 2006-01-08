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

// VTypes.h

// RFB V3.0

// Datatypes used by the VGui system

#if (!defined(_ATT_VTYPES_DEFINED))
#define _ATT_VTYPES_DEFINED

////////////////////////////
// Numeric data types

////////////////////////////
// Fixed size (derived from rfb.h)

typedef unsigned int VCard32;
typedef unsigned short VCard16;
typedef unsigned char VCard8;
typedef int VInt32;
typedef short VInt16;
typedef char VInt8;

////////////////////////////
// Variable size
//		These will always be at least as big as the largest
//		fixed-size data-type

typedef VCard32 VCard;
typedef VInt32 VInt;

////////////////////////////
// Useful functions on integers

static inline VInt Max(VInt x, VInt y) {if (x>y) return x; else return y;}
static inline VInt Min(VInt x, VInt y) {if (x<y) return x; else return y;}

////////////////////////////
// Boolean

typedef int VBool;
const VBool VTrue = -1;
const VBool VFalse = 0;

////////////////////////////
// Others

typedef char VChar;
#if (!defined(NULL))
#define NULL 0
#endif

////////////////////////////
// Compound data types

// #include "rfbgui/VPoint.h"
// #include "rfbgui/VRect.h"
typedef VChar * VString;

#endif // _ATT_VTYPES_DEFINED





