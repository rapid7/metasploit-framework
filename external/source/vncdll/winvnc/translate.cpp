/*
 * translate.c - translate between different pixel formats
 */

/*
 *  Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.
 *
 *  This is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This software is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this software; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 *  USA.
 */

#include "stdhdrs.h"

#include "translate.h"
#include <stdio.h>
#include "rfb.h"

#define CONCAT2(a,b) a##b
#define CONCAT2E(a,b) CONCAT2(a,b)
#define CONCAT4(a,b,c,d) a##b##c##d
#define CONCAT4E(a,b,c,d) CONCAT4(a,b,c,d)

#define OUTBPP 8
#include "tableinittctemplate.cpp"
#include "tableinitcmtemplate.cpp"
#define INBPP 8
#include "tabletranstemplate.cpp"
#undef INBPP
#define INBPP 16
#include "tabletranstemplate.cpp"
#undef INBPP
#define INBPP 32
#include "tabletranstemplate.cpp"
#undef INBPP
#undef OUTBPP

#define OUTBPP 16
#include "tableinittctemplate.cpp"
#include "tableinitcmtemplate.cpp"
#define INBPP 8
#include "tabletranstemplate.cpp"
#undef INBPP
#define INBPP 16
#include "tabletranstemplate.cpp"
#undef INBPP
#define INBPP 32
#include "tabletranstemplate.cpp"
#undef INBPP
#undef OUTBPP

#define OUTBPP 32
#include "tableinittctemplate.cpp"
#include "tableinitcmtemplate.cpp"
#define INBPP 8
#include "tabletranstemplate.cpp"
#undef INBPP
#define INBPP 16
#include "tabletranstemplate.cpp"
#undef INBPP
#define INBPP 32
#include "tabletranstemplate.cpp"
#undef INBPP
#undef OUTBPP

rfbInitTableFnType rfbInitTrueColourSingleTableFns[3] = {
    rfbInitTrueColourSingleTable8,
    rfbInitTrueColourSingleTable16,
    rfbInitTrueColourSingleTable32
};

rfbInitTableFnType rfbInitColourMapSingleTableFns[3] = {
    rfbInitColourMapSingleTable8,
    rfbInitColourMapSingleTable16,
    rfbInitColourMapSingleTable32
};

rfbInitTableFnType rfbInitTrueColourRGBTablesFns[3] = {
    rfbInitTrueColourRGBTables8,
    rfbInitTrueColourRGBTables16,
    rfbInitTrueColourRGBTables32
};

rfbTranslateFnType rfbTranslateWithSingleTableFns[3][3] = {
    { rfbTranslateWithSingleTable8to8,
      rfbTranslateWithSingleTable8to16,
      rfbTranslateWithSingleTable8to32 },
    { rfbTranslateWithSingleTable16to8,
      rfbTranslateWithSingleTable16to16,
      rfbTranslateWithSingleTable16to32 },
    { rfbTranslateWithSingleTable32to8,
      rfbTranslateWithSingleTable32to16,
      rfbTranslateWithSingleTable32to32 }
};

rfbTranslateFnType rfbTranslateWithRGBTablesFns[3][3] = {
    { rfbTranslateWithRGBTables8to8,
      rfbTranslateWithRGBTables8to16,
      rfbTranslateWithRGBTables8to32 },
    { rfbTranslateWithRGBTables16to8,
      rfbTranslateWithRGBTables16to16,
      rfbTranslateWithRGBTables16to32 },
    { rfbTranslateWithRGBTables32to8,
      rfbTranslateWithRGBTables32to16,
      rfbTranslateWithRGBTables32to32 }
};



// rfbTranslateNone is used when no translation is required.

void
rfbTranslateNone(char *table, rfbPixelFormat *in, rfbPixelFormat *out,
		 char *iptr, char *optr, int bytesBetweenInputLines,
		 int width, int height)
{
    int bytesPerOutputLine = width * (out->bitsPerPixel / 8);

    while (height > 0) {
	memcpy(optr, iptr, bytesPerOutputLine);
	iptr += bytesBetweenInputLines;
	optr += bytesPerOutputLine;
	height--;
    }
}

