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


// vncRegion implementation
// This implementation uses the system region handling routines
// to speed things up and give the best results

#include "stdhdrs.h"

// Header

#include "vncRegion.h"

// Implementation

vncRegion::vncRegion()
{
	region = NULL;
}

vncRegion::~vncRegion()
{
	Clear();
}

void vncRegion::AddRect(const RECT &new_rect)
{
	HRGN newregion;

	if (region == NULL)
	{
		// Create the region and set it to contain this rectangle
		region = CreateRectRgnIndirect(&new_rect);
	}
	else
	{
		// Create a new region containing the appropriate rectangle
		newregion = CreateRectRgnIndirect(&new_rect);

		// Merge it into the existing region
		if (CombineRgn(region, region, newregion, RGN_OR) == NULLREGION)
			Clear();

		// Now delete the temporary region
		DeleteObject(newregion);
	}
}

void vncRegion::AddRect(RECT R, int xoffset, int yoffset)
{
	R.left += xoffset;
	R.top += yoffset;
	R.right += xoffset;
	R.bottom += yoffset;
	AddRect(R);
}

void vncRegion::SubtractRect(RECT &new_rect)
{
	HRGN newregion;

	if (region == NULL)
		return;

	// Create a new region containing the appropriate rectangle
	newregion = CreateRectRgnIndirect(&new_rect);

	// Remove it from the existing region
	if (CombineRgn(region, region, newregion, RGN_DIFF) == NULLREGION)
		Clear();

	// Now delete the temporary region
	DeleteObject(newregion);
}

void vncRegion::Clear()
{
	// Set the region to be empty
	if (region != NULL)
	{
		DeleteObject(region);
		region = NULL;
	}
}

void
vncRegion::Combine(vncRegion &rgn)
{
	if (rgn.region == NULL)
		return;
	if (region == NULL)
	{
		region = CreateRectRgn(0, 0, 0, 0);
		if (region == NULL)
			return;

		// Copy the specified region into this one...
		if (CombineRgn(region, rgn.region, 0, RGN_COPY) == NULLREGION)
			Clear();
		return;
	}

	// Otherwise, combine the two
	if (CombineRgn(region, region, rgn.region, RGN_OR) == NULLREGION)
		Clear();
}

void
vncRegion::Intersect(vncRegion &rgn)
{
	if (rgn.region == NULL)
		return;
	if (region == NULL)
		return;

	// Otherwise, intersect the two
	if (CombineRgn(region, region, rgn.region, RGN_AND) == NULLREGION)
		Clear();
}

void
vncRegion::Subtract(vncRegion &rgn)
{
	if (rgn.region == NULL)
		return;
	if (region == NULL)
		return;

	// Otherwise, intersect the two
	if (CombineRgn(region, region, rgn.region, RGN_DIFF) == NULLREGION)
		Clear();
}



// Return all the rectangles
BOOL vncRegion::Rectangles(rectlist &rects)
{
	int buffsize;
	DWORD x;
	RGNDATA *buff;

	// If the region is empty then return empty rectangle list
	if (region == NULL)
		return FALSE;

	// Get the size of buffer required
	buffsize = GetRegionData(region, NULL, 0);
	buff = (RGNDATA *) new BYTE [buffsize];
	if (buff == NULL)
		return FALSE;

	// Now get the region data
	if (GetRegionData(region, buffsize, buff))
	{
		for (x=0; x<(buff->rdh.nCount); x++)
		{
			// Obtain the rectangles from the list
			RECT *rect = (RECT *) (((BYTE *) buff) + sizeof(RGNDATAHEADER) + x * sizeof(RECT));
			rects.push_front(*rect);
		}
	}

	// Delete the temporary buffer
	delete [] buff;

	// Return whether there are any rects!
	return !rects.empty();
}

// Return rectangles clipped to a certain area
BOOL vncRegion::Rectangles(rectlist &rects, RECT &cliprect)
{
	vncRegion cliprgn;

	// Create the clip-region
	cliprgn.AddRect(cliprect);

	// Calculate the intersection with this region
	cliprgn.Intersect(*this);

	return cliprgn.Rectangles(rects);
}
