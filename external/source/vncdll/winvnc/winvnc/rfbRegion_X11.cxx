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

// Cross-platform Region class based on the X11 region implementation

#include "stdhdrs.h"
#include "rfbRegion_X11.h"
#include <Xregion/region.h>
#include <assert.h>

using namespace rfb;

class _RectRegion {
public:
  _RectRegion() {
    region.rects = 0;
    region.numRects = 0;
    region.size = 0;
  }
  _RectRegion(const Rect& r) {
    region.rects = &region.extents;
    region.numRects = 1;
    region.extents.x1 = r.tl.x;
    region.extents.y1 = r.tl.y;
    region.extents.x2 = r.br.x;
    region.extents.y2 = r.br.y;
    region.size = 1;
    if (r.is_empty())
      region.numRects = 0;
  }
  REGION region;
};


Region::Region() {
  Xrgn = XCreateRegion();
  assert(Xrgn);
}

Region::Region(int x1, int y1, int x2, int y2) {
  Xrgn = XCreateRegion();
  assert(Xrgn);
  reset(Rect(x1, y1, x2, y2));
}

Region::Region(const Rect& r) {
  Xrgn = XCreateRegion();
  assert(Xrgn);
  reset(r);
}

Region::Region(const Region& r) {
  _RectRegion tmp;
  Xrgn = XCreateRegion();
  assert(Xrgn);
  XUnionRegion(&tmp.region, r.Xrgn, Xrgn);
}

Region::~Region() {
  XDestroyRegion(Xrgn);
}


rfb::Region& Region::operator=(const Region& r) {
  _RectRegion tmp;
  clear();
  XUnionRegion(&tmp.region, r.Xrgn, Xrgn);
  return *this;
}


void Region::clear() {
  EMPTY_REGION(Xrgn);
}

void Region::reset(const Rect& r) {
  clear();
  XRectangle xrect;
  xrect.x = r.tl.x;
  xrect.y = r.tl.y;
  xrect.width = r.width();
  xrect.height = r.height();
  XUnionRectWithRegion(&xrect, Xrgn, Xrgn);
}

void Region::translate(const Point& delta) {
  XOffsetRegion(Xrgn, delta.x, delta.y);
}

void Region::setOrderedRects(const std::vector<Rect>& rects) {
  std::vector<Rect>::const_iterator i;
  for (i=rects.begin(); i != rects.end(); i++) {
    _RectRegion rr(*i);
    XUnionRegion(&rr.region, Xrgn, Xrgn);
  }
}


void Region::assign_intersect(const Region& r) {
  XIntersectRegion(r.Xrgn, Xrgn, Xrgn);
}

void Region::assign_union(const Region& r) {
  XUnionRegion(r.Xrgn, Xrgn, Xrgn);
}

void Region::assign_subtract(const Region& r) {
  XSubtractRegion(Xrgn, r.Xrgn, Xrgn);
}


rfb::Region Region::intersect(const Region& r) const {
  Region t = *this;
  t.assign_intersect(r);
  return t;
}

rfb::Region Region::union_(const Region& r) const {
  Region t = *this;
  t.assign_union(r);
  return t;
}

rfb::Region Region::subtract(const Region& r) const {
  Region t = *this;
  t.assign_subtract(r);
  return t;
}


bool Region::equals(const Region& b) const {
  return XEqualRegion(Xrgn, b.Xrgn);
}

bool Region::is_empty() const {
  return XEmptyRegion(Xrgn);
}


bool Region::get_rects(std::vector<Rect>& rects,
                       bool left2right,
                       bool topdown) const {
  BOX* Xrects = Xrgn->rects;

  int nRects = Xrgn->numRects;
  int xInc = left2right ? 1 : -1;
  int yInc = topdown ? 1 : -1;
  int i = topdown ? 0 : nRects-1;

  while (nRects > 0) {
    int firstInNextBand = i;
    int nRectsInBand = 0;

    while (nRects > 0 && Xrects[firstInNextBand].y1 == Xrects[i].y1) {
      firstInNextBand += yInc;
      nRects--;
      nRectsInBand++;
    }

    if (xInc != yInc)
      i = firstInNextBand - yInc;

    while (nRectsInBand > 0) {
      Rect r(Xrects[i].x1, Xrects[i].y1,
             Xrects[i].x2, Xrects[i].y2);
      rects.push_back(r);
      i += xInc;
      nRectsInBand--;
    }

    i = firstInNextBand;
  }

  return !rects.empty();
}

rfb::Rect Region::get_bounding_rect() const {
  XRectangle r;
  XClipBox(Xrgn, &r);
  return Rect(r.x, r.y, r.x+r.width, r.y+r.height);
}


XRegion Region::replaceXrgn(XRegion newrgn) {
  XRegion tmp = Xrgn;
  Xrgn = newrgn;
  return tmp;
}
