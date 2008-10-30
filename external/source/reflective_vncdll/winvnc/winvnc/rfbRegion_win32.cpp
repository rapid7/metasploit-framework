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

// -=- rfbRegion_win32.cpp
// Win32 implementation of the rfb::Region2D class

#include <assert.h>

#include "stdhdrs.h"
#include "rfbRegion_win32.h"
#include <omnithread.h>

// ***
#include <set>
std::set<HRGN> regions;

using namespace rfb;

static omni_mutex region_lock;

static int maxrgnrects = 0;

static void abortRgnCode(DWORD error=0) {
  omni_mutex_lock l(region_lock);
  int numregions = regions.size();
  int maxregionsize = maxrgnrects;
  int err = error;
  std::set<HRGN>::const_iterator i;
  int rgnbufsize = 0;
  for (i=regions.begin(); i!=regions.end(); i++) {
    rgnbufsize += GetRegionData(*i, 0, NULL);
  }
  abort();
}

static void assertValidRegion(HRGN hRgn) {
  omni_mutex_lock l(region_lock);
  RECT r;
  DWORD buffsize = GetRegionData(hRgn, 0, NULL);
  if (buffsize == 0) abortRgnCode();
  maxrgnrects = max(maxrgnrects, (buffsize-sizeof(RGNDATAHEADER))/sizeof(RECT));
}

Region2D::Region2D() {
  omni_mutex_lock l(region_lock);
	hRgn = CreateRectRgn(0, 0, 0, 0);
	assertValidRegion(hRgn);

  // ***
  regions.insert(hRgn);
}

Region2D::Region2D(int x1, int y1, int x2, int y2) {
  omni_mutex_lock l(region_lock);
	hRgn = CreateRectRgn(x1, y1, x2, y2);
  assertValidRegion(hRgn);

  // ***
  regions.insert(hRgn);
}

Region2D::Region2D(const Rect &r) {
  omni_mutex_lock l(region_lock);
	hRgn = CreateRectRgn(r.tl.x, r.tl.y, r.br.x, r.br.y);
	assertValidRegion(hRgn);

  // ***
  regions.insert(hRgn);
}
	
Region2D::Region2D(const Region2D &r) {
  omni_mutex_lock l(region_lock);
	hRgn = CreateRectRgn(0, 0, 1, 1);
	assertValidRegion(hRgn);
  if (CombineRgn(hRgn, r.hRgn, NULL, RGN_COPY) == ERROR)
    abortRgnCode(GetLastError());
  assertValidRegion(hRgn);
  assertValidRegion(r.hRgn);

  // ***
  regions.insert(hRgn);
}

Region2D::~Region2D() {
  omni_mutex_lock l(region_lock);

  // ***
  regions.erase(hRgn);

	assertValidRegion(hRgn);
  if (!DeleteObject(hRgn))
    abortRgnCode(GetLastError());
  hRgn = 0;
}

Region2D& Region2D::operator=(const Region2D &src) {
  // *** omni_mutex_lock l(region_lock);
	assertValidRegion(hRgn); assertValidRegion(src.hRgn);
  if (CombineRgn(hRgn, src.hRgn, NULL, RGN_COPY) == ERROR)
    abortRgnCode(GetLastError());
	assertValidRegion(hRgn); assertValidRegion(src.hRgn);
	return *this;
}

Region2D Region2D::intersect(const Region2D &src) const {
  // *** omni_mutex_lock l(region_lock);
	Region2D result;
	assertValidRegion(result.hRgn); assertValidRegion(hRgn); assertValidRegion(src.hRgn);
	if (CombineRgn(result.hRgn, src.hRgn, hRgn, RGN_AND) == ERROR)
    abortRgnCode(GetLastError());
	assertValidRegion(result.hRgn); assertValidRegion(src.hRgn); assertValidRegion(hRgn);
	return result;
}
	
Region2D Region2D::union_(const Region2D &src) const {
  // *** omni_mutex_lock l(region_lock);
	Region2D result;
	assertValidRegion(result.hRgn); assertValidRegion(hRgn); assertValidRegion(src.hRgn);
	if (CombineRgn(result.hRgn, src.hRgn, hRgn, RGN_OR) == ERROR)
    abortRgnCode(GetLastError());
	assertValidRegion(result.hRgn); assertValidRegion(src.hRgn); assertValidRegion(hRgn);
	return result;
}
	
Region2D Region2D::subtract(const Region2D &src) const {
  // *** omni_mutex_lock l(region_lock);
	Region2D result;
	assertValidRegion(result.hRgn); assertValidRegion(hRgn); assertValidRegion(src.hRgn);
	if (CombineRgn(result.hRgn, hRgn, src.hRgn, RGN_DIFF) == ERROR)
    abortRgnCode(GetLastError());
	assertValidRegion(result.hRgn); assertValidRegion(hRgn); assertValidRegion(src.hRgn);
	return result;
}

void Region2D::reset(int x1, int y1, int x2, int y2) {
  // *** omni_mutex_lock l(region_lock);
	assertValidRegion(hRgn);
  if (!SetRectRgn(hRgn, x1, y1, x2, y2))
    abortRgnCode(GetLastError());
	assertValidRegion(hRgn);
}

void Region2D::translate(const rfb::Point &p) {
  // *** omni_mutex_lock l(region_lock);
	assertValidRegion(hRgn);
  if (OffsetRgn(hRgn, p.x, p.y) == ERROR)
    abortRgnCode(GetLastError());
	assertValidRegion(hRgn);
}

bool Region2D::get_rects(RectVector &rects, bool left2right, bool topdown) const {
  // *** omni_mutex_lock l(region_lock);

	assertValidRegion(hRgn);

  DWORD buffsize = GetRegionData(hRgn, 0, NULL);
  if (!buffsize)
    abortRgnCode(GetLastError());

  assert(hRgn);
  if (is_empty())
    return false;

	unsigned char*buffer = new unsigned char[buffsize];
	assert(buffer);

  if (GetRegionData(hRgn, buffsize, (LPRGNDATA)buffer) != buffsize)
    abortRgnCode(GetLastError());

	LPRGNDATA region_data = (LPRGNDATA)buffer;
	DWORD nCount = region_data->rdh.nCount;
	if (topdown) {
		long current_y = INT_MIN;
		long start_i=0, end_i=-1;
		rects.reserve(nCount);
		for (long i=0; i<nCount; i++) {
			Rect rect = ((RECT*)&region_data->Buffer[0])[i];
			if (rect.tl.y == current_y) {
				end_i = i;
			} else {
				if (left2right) {
					for (long j=start_i; j<=end_i; j++) {
						Rect r = ((RECT*)&region_data->Buffer[0])[j];
						rects.push_back(r);
					}
				} else {
					for (long j=end_i; j>=start_i; j--) {
						Rect r = ((RECT*)&region_data->Buffer[0])[j];
						rects.push_back(r);
					}
				}
				start_i = i;
				end_i = i;
				current_y = rect.tl.y;
			}
		}
		if (left2right) {
			for (long j=start_i; j<=end_i; j++) {
				Rect r = ((RECT*)&region_data->Buffer[0])[j];
				rects.push_back(r);
			}
		} else {
			for (long j=end_i; j>=start_i; j--) {
				Rect r = ((RECT*)&region_data->Buffer[0])[j];
				rects.push_back(r);
			}
		}
	} else {
		long current_y = INT_MIN;
		long start_i=nCount, end_i=nCount-1;
		rects.reserve(nCount);
		for (long i=nCount-1; i>=0; i--) {
			Rect rect = ((RECT*)&region_data->Buffer[0])[i];
			if (rect.tl.y == current_y) {
				start_i = i;
			} else {
				if (left2right) {
					for (long j=start_i; j<=end_i; j++) {
						Rect r = ((RECT*)&region_data->Buffer[0])[j];
						rects.push_back(r);
					}
				} else {
					for (long j=end_i; j>=start_i; j--) {
						Rect r = ((RECT*)&region_data->Buffer[0])[j];
						rects.push_back(r);
					}
				}
				end_i = i;
				start_i = i;
				current_y = rect.tl.y;
			}
		}
		if (left2right) {
			for (long j=start_i; j<=end_i; j++) {
				Rect r = ((RECT*)&region_data->Buffer[0])[j];
				rects.push_back(r);
			}
		} else {
			for (long j=end_i; j>=start_i; j--) {
				Rect r = ((RECT*)&region_data->Buffer[0])[j];
				rects.push_back(r);
			}
		}
	}

	delete [] buffer;
  assert(!rects.empty());
  assertValidRegion(hRgn);

  return true;
}

Rect Region2D::get_bounding_rect() const {
  // *** omni_mutex_lock l(region_lock);
  RECT result;
	assertValidRegion(hRgn);
  if (!GetRgnBox(hRgn, &result))
    abortRgnCode(GetLastError());
	assertValidRegion(hRgn);
	return result;
}

void Region2D::clear() {
  // *** omni_mutex_lock l(region_lock);
	assertValidRegion(hRgn);
  if (!SetRectRgn(hRgn, 0, 0, 0, 0))
    abortRgnCode(GetLastError());
	assertValidRegion(hRgn);
}

bool Region2D::equals(const Region2D &b) const {
  // *** omni_mutex_lock l(region_lock);
	assertValidRegion(hRgn); assertValidRegion(b.hRgn);
	BOOL result = EqualRgn(b.hRgn, hRgn);
  if (result == ERROR)
    abortRgnCode(GetLastError());
	assertValidRegion(hRgn); assertValidRegion(b.hRgn);
  return result;
}

bool Region2D::is_empty() const {
  // *** omni_mutex_lock l(region_lock);
	RECT result;
	assertValidRegion(hRgn);
  int kind = GetRgnBox(hRgn, &result);
  if (!kind)
    abortRgnCode(GetLastError());
	assertValidRegion(hRgn);
  return kind == NULLREGION;
}
