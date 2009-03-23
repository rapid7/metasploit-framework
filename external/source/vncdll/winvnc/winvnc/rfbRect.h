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

// rfb::Rect and rfb::Point structures

#ifndef __RFB_RECT_INCLUDED__
#define __RFB_RECT_INCLUDED__

#ifdef WIN32
#include <windows.h>
#endif

#include "rfbMisc.h"
#include <vector>

namespace rfb {

	// rfb::Point
	//
	// Represents a point in 2D space, by X and Y coordinates.
	// Can also be used to represent a delta, or offset, between
	// two Points.
	// Functions are provided to allow Points to be compared for
	// equality and translated by a supplied offset.
	// Functions are also provided to negate offset Points.

	struct Point {
		Point() : x(0), y(0) {}
		Point(int x_, int y_) : x(x_), y(y_) {}
#ifdef WIN32
		Point(const POINT &p) : x(p.x), y(p.y) {}
#endif
		Point negate() const {return Point(-x, -y);}
		bool equals(const Point &p) const {return x==p.x && y==p.y;}
		Point translate(const Point &p) const {return Point(x+p.x, y+p.y);}
		int x, y;
	};

	// rfb::Rect
	//
	// Represents a rectangular region defined by its top-left (tl)
	// and bottom-right (br) Points.
	// Rects may be compared for equality, checked to determine whether
	// or not they are empty, cleared (made empty), or intersected with
	// one another.  The bounding rectangle of two existing Rects
	// may be calculated, as may the area of a Rect.
	// Rects may also be translated, in the same way as Points, by
	// an offset specified in a Point structure.

	struct Rect {
		Rect() {}
		Rect(Point tl_, Point br_) : tl(tl_), br(br_) {}
		Rect(int x1, int y1, int x2, int y2) : tl(x1, y1), br(x2, y2) {}
#ifdef WIN32
		Rect(const RECT &r) : tl(r.left, r.top), br(r.right, r.bottom) {}
#endif
		Rect intersect(const Rect &r) const {
			Rect result;
			result.tl.x = max(tl.x, r.tl.x);
			result.tl.y = max(tl.y, r.tl.y);
			result.br.x = min(br.x, r.br.x);
			result.br.y = min(br.y, r.br.y);
			return result;
		}
		Rect union_boundary(const Rect &r) const {
			Rect result;
			result.tl.x = min(tl.x, r.tl.x);
			result.tl.y = min(tl.y, r.tl.y);
			result.br.x = max(br.x, r.br.x);
			result.br.y = max(br.y, r.br.y);
			return result;
		}
		Rect translate(const Point &p) const {
			return Rect(tl.translate(p), br.translate(p));
		}
		bool equals(const Rect &r) const {return r.tl.equals(tl) && r.br.equals(br);}
		bool is_empty() const {return (tl.x >= br.x) || (tl.y >= br.y);}
		void clear() {tl = Point(); br = Point();}
		bool enclosed_by(const Rect &r) const {
			return (tl.x>=r.tl.x) && (tl.y>=r.tl.y) && (br.x<=r.br.x) && (br.y<=r.br.y);
		}
		unsigned int area() const {return is_empty() ? 0 : width()*height();}
    inline int width() const {return br.x-tl.x;}
    inline int height() const {return br.y-tl.y;}
		Point tl;
		Point br;
	};

	// rfb::RectVector
	//
	// An STL vector containing Rects. 
	typedef std::vector<Rect> RectVector;

};


#endif // __RFB_RECT_INCLUDED__