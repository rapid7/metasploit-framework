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


/* translate.h - prototypes of functions in translate.cpp */

#ifndef TRANSLATE_H__
#define TRANSLATE_H__

#include "stdhdrs.h"
#include "rfb.h"

// Translate function prototype!
typedef void (*rfbTranslateFnType)(char *table, rfbPixelFormat *in,
				   rfbPixelFormat *out,
				   char *iptr, char *optr,
				   int bytesBetweenInputLines,
				   int width, int height);

// Init function prototype!
typedef void (*rfbInitTableFnType)(char **table, rfbPixelFormat *in,
				   rfbPixelFormat *out);


// External translation stuff
extern void rfbTranslateNone(char *table, rfbPixelFormat *in,
			     rfbPixelFormat *out,
			     char *iptr, char *optr,
			     int bytesBetweenInputLines,
			     int width, int height);

// Macro to compare pixel formats.
#define PF_EQ(x,y)												\
	((x.bitsPerPixel == y.bitsPerPixel) &&						\
	 (x.depth == y.depth) &&									\
	 (x.trueColour == y.trueColour) &&							\
	 ((x.bigEndian == y.bigEndian) || (x.bitsPerPixel == 8)) &&	\
	 (!x.trueColour || ((x.redMax == y.redMax) &&				\
			   (x.greenMax == y.greenMax) &&					\
			   (x.blueMax == y.blueMax) &&						\
			   (x.redShift == y.redShift) &&					\
			   (x.greenShift == y.greenShift) &&				\
			   (x.blueShift == y.blueShift))))

// Translation functions themselves
extern rfbInitTableFnType rfbInitTrueColourSingleTableFns[];
extern rfbInitTableFnType rfbInitColourMapSingleTableFns[];
extern rfbInitTableFnType rfbInitTrueColourRGBTablesFns[];
extern rfbTranslateFnType rfbTranslateWithSingleTableFns[3][3];
extern rfbTranslateFnType rfbTranslateWithRGBTablesFns[3][3];

/*
extern Bool rfbSetTranslateFunction(rfbClientPtr cl);
extern void rfbSetClientColourMaps(int firstColour, int nColours);
extern Bool rfbSetClientColourMap(rfbClientPtr cl, int firstColour,
				  int nColours);
*/

#endif
