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


// vncRegion object

// The vncRegion object turns a number of rectangular regions
// into a list of distinct, non-overlapping regions.

class vncRegion;

#if !defined(VNCREGION_DEFINED)
#define VNCREGION_DEFINED
#pragma once

#include "stdhdrs.h"
#include <list>
#include "RectList.h"

// Class definition
class vncRegion
{

// Fields
public:

// Methods
public:
	// Create/Destroy methods
	vncRegion();
	~vncRegion();

	void AddRect(const RECT &rect);			// Add another rectangle to the regions
	void AddRect(RECT rect, int xoffset, int yoffset);	// ... with offset
	void SubtractRect(RECT &rect);			// Subtract a rectangle from the regions
	void Clear();							// Clear the current set of rectangles
	inline BOOL IsEmpty() {					// Is the region empty?
		return region == NULL;
	}
	void Combine(vncRegion &rgn);			// Combine with another region
	void Intersect(vncRegion &rgn);			// Intersect with another region
	void Subtract(vncRegion &rgn);			// Subtract another region from this one

	// Rectangle retrieval routines - return FALSE if no rects returned!
	// Note that these routines ADD rectangles to existing lists...
	BOOL Rectangles(rectlist &rects);					// Just return the rects
	BOOL Rectangles(rectlist &rects, RECT &cliprect);	// Return all rects within the clip region	

// Implementation
protected:
	HRGN region;							// Region used internally
};

#endif // VNCREGION_DEFINED
