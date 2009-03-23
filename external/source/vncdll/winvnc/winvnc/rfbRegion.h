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

#define USE_X11_REGIONS

#ifdef USE_X11_REGIONS
#include "rfbRegion_X11.h"
#else

#ifdef WIN32
#include "rfbRegion_win32.h"
#else

#error "using custom region code"

// rfb::Region and rfb::Region2D classes

#ifndef __RFB_REGION_INCLUDED__
#define __RFB_REGION_INCLUDED__

#include "rfbRect.h"
#include <vector>

namespace rfb {

	struct Span;

	// rfb::Region
	//
	// The Region class is used to represent N-dimensional
	// regions. 
	// Each Region is a one-dimensional collection of
	// non-overlapping Spans.  Each span may itself contain
	// a child Region, thus allowing multi-dimensional
	// regions to be expressed.
	//
	// Regions may be infinite, empty or non-empty.

	class Region {
	public:
		Region(bool infinite_=false);
		Region(int start, int end, const Region &sub);

		Region intersect(const Region &src) const {
			Region tmp; do_intersect(tmp, src); return tmp;
		}
		Region union_(const Region &src) const {
			Region tmp; do_union_(tmp, src); return tmp;
		}
		Region subtract(const Region &src) const {
			Region tmp; do_subtract(tmp, src); return tmp;
		}

		void translate(const int offset);
		void reset(int start, int end, const Region &subspans);
		void clear();

		bool equals(const Region &b) const;
		bool is_empty() const {return spans.empty() && !infinite;};
		bool is_infinite() const {return infinite;};

		const std::vector<Span> &get_spans() const {return spans;};
		Span get_extent() const;

		void debug_print(const char *prefix) const;

	protected:
		void do_intersect(Region &dest, const Region &src) const;
		void do_union_(Region &dest, const Region &src) const;
		void do_subtract(Region &dest, const Region &src) const;

	protected:
		bool infinite;
		std::vector<Span> spans;
	};

	class Region2D : public Region {
	public:
		Region2D();
		Region2D(int x1, int y1, int x2, int y2);
		Region2D(const Rect &r);
		Region2D intersect(const Region2D &src) const {
			Region2D tmp; do_intersect(tmp, src); return tmp;
		}
		Region2D union_(const Region2D &src) const {
			Region2D tmp; do_union_(tmp, src); return tmp;
		}
		Region2D subtract(const Region2D &src) const {
			Region2D tmp; do_subtract(tmp, src); return tmp;
		}
		void reset(int x1, int y1, int x2, int y2);
		void translate(const rfb::Point &p);
		bool get_rects(rfb::RectVector &rects, bool left2right, bool topdown) const;
		Rect get_bounding_rect() const;
	};

	struct Span {
		Span() : start(0), end(0) {};
		Span(int start, int end, const Region &r);
		bool equals(const Span &b) const;
		void append_to(std::vector<Span> &spans) const;
		int start;
		int end;
		Region subspans;
	};

	typedef std::vector<Span> SpanVector;
};

#endif // __RFB_REGION_INCLUDED__

#endif // WIN32

#endif // X11
