//  Copyright (C) 2002-2003 RealVNC Ltd. All Rights Reserved.
//
//  This program is free software; you can redistribute it and/or modify
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
// If the source code for the program is not available from the place from
// which you received this file, check http://www.realvnc.com/ or contact
// the authors on info@realvnc.com for information on obtaining it.

// rfb::Region2D class for Win32

#ifndef __RFB_REGION_WIN32_INCLUDED__
#define __RFB_REGION_WIN32_INCLUDED__

#include "rfbRect.h"
#include <vector>

namespace rfb {

	// rfb::Region2D
	//
	// See the rfbRegion.h header for documentation.

	class Region2D {
	public:
		Region2D();
		Region2D(int x1, int y1, int x2, int y2);
		Region2D(const Rect &r);
		Region2D(const Region2D &r);
		~Region2D();

		Region2D intersect(const Region2D &src) const;
		Region2D union_(const Region2D &src) const;
		Region2D subtract(const Region2D &src) const;
		Region2D &operator=(const Region2D &src);
		void reset(int x1, int y1, int x2, int y2);
		void translate(const rfb::Point &p);
		bool get_rects(rfb::RectVector &rects, bool left2right, bool topdown) const;
		Rect get_bounding_rect() const;

		void clear();

		bool equals(const Region2D &b) const;
		bool is_empty() const;

    HRGN getHandle() const {return hRgn;};
	private:
		HRGN hRgn;
	};
};

#endif __RFB_REGION_WIN32_INCLUDED__


