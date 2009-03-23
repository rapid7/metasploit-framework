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

// -=- rfbUpdateTracker.cpp
//
// Tracks updated regions and a region-copy event, too
//

#include "stdhdrs.h"

#include <assert.h>

#include "rfbUpdateTracker.h"

using namespace rfb;

// ClippedUpdateTracker

void ClippedUpdateTracker::add_changed(const Region2D &region) {
	child.add_changed(region.intersect(cliprgn));
}

void ClippedUpdateTracker::add_copied(const Region2D &dest, const Point &delta) {
	// Clip the destination to the display area
	Region2D tmp = dest.intersect(cliprgn);
	if (tmp.is_empty())	return;

	// Clip the source to the screen
	tmp.translate(delta.negate());
	tmp = tmp.intersect(cliprgn);
	if (!tmp.is_empty()) {
		// Translate the source back to a destination region
		tmp.translate(delta);

		// Pass the copy region to the child tracker
		child.add_copied(tmp, delta);
	}

	// And add any bits that we had to remove to the changed region
	tmp = dest.subtract(tmp);
	if (!tmp.is_empty()) {
		child.add_changed(tmp);
	}
}

// SimpleUpdateTracker

SimpleUpdateTracker::SimpleUpdateTracker(bool use_copyrect) {
	copy_enabled = use_copyrect;
}

SimpleUpdateTracker::~SimpleUpdateTracker() {
}

void SimpleUpdateTracker::add_changed(const Region2D &region) {
	changed = changed.union_(region);
}

void SimpleUpdateTracker::add_copied(const Region2D &dest, const Point &delta) {
	// Do we support copyrect?
	if (!copy_enabled) {
		add_changed(dest);
		return;
	}

	// Is there anything to do?
	if (dest.is_empty()) return;

	// Calculate whether any of this copy can be treated as a continuation
	// of an earlier one
	Region2D src = dest;
	src.translate(delta.negate());
	Region2D overlap = src.intersect(copied);

	if (overlap.is_empty()) {
		// There is no overlap

		Rect newbr = dest.get_bounding_rect();
		Rect oldbr = copied.get_bounding_rect();
		if (oldbr.area() > newbr.area()) {
			// Old copyrect is (probably) bigger - use it
			changed = changed.union_(dest);
		} else {
			// New copyrect is probably bigger
      Region2D invalid = src.intersect(changed);
      invalid.translate(delta);
      changed = changed.union_(invalid).union_(copied);
      copied = dest.subtract(invalid);
      copy_delta = delta;
/*
			// Use the new one
			// But be careful not to copy stuff that still needs
			// to be updated.
			Region2D invalid_src = src.intersect(changed);
			invalid_src.translate(delta);
			changed = changed.union_(invalid_src).union_(copied);
			copied = dest;
			copy_delta = delta;
      */
		}
		return;
	}

  Region2D valid = overlap.subtract(changed);
  valid.translate(delta);
  changed = changed.union_(copied).union_(dest).subtract(valid);
  copied = valid;
  copy_delta = copy_delta.translate(delta);

  /*
	Region2D invalid_src = overlap.intersect(changed);
	invalid_src.translate(delta.negate());
	changed = changed.union_(invalid_src);
	
	overlap.translate(delta);

	Region2D nonoverlapped_copied = dest.union_(copied).subtract(overlap);
	changed = changed.union_(nonoverlapped_copied);

	copied = overlap;
	copy_delta = copy_delta.translate(delta);
  */

	return;
}

void SimpleUpdateTracker::flush_update(UpdateInfo &info, const Region2D &cliprgn) {
	copied = copied.subtract(changed);

	// Ensure the UpdateInfo structure is empty
	info.copied.clear();
	info.changed.clear();

	// Clip the changed region to the clip region
	Region2D updatergn = changed.intersect(cliprgn);
	changed = changed.subtract(updatergn);

	// Clip the copyrect region to the display
	Region2D copyrgn = copied.intersect(cliprgn);
	copied = copied.subtract(copyrgn);

	// Save the update and copyrect rectangles info the UpdateInfo
	updatergn.get_rects(info.changed, 1, 1);
	copyrgn.get_rects(info.copied, copy_delta.x <= 0, copy_delta.y <= 0);
	info.copy_delta = copy_delta;
}
void SimpleUpdateTracker::flush_update(UpdateTracker &info, const Region2D &cliprgn) {
	Region2D copied_clipped = copied.intersect(cliprgn);
	Region2D changed_clipped = changed.intersect(cliprgn);
	copied = copied.subtract(copied_clipped);
	changed = changed.subtract(changed_clipped);
	if (!copied_clipped.is_empty()) {
		info.add_copied(copied_clipped, copy_delta);
	}
	if (!changed_clipped.is_empty())
		info.add_changed(changed_clipped);
}

void SimpleUpdateTracker::get_update(UpdateInfo &info) const {
	info.copied.clear();
	info.changed.clear();
	info.copy_delta = copy_delta;
	Region2D copied_dest = copied.subtract(changed);
	copied_dest.get_rects(info.copied, copy_delta.x <= 0, copy_delta.y <= 0);
	changed.get_rects(info.changed, 1, 1);
}
void SimpleUpdateTracker::get_update(UpdateTracker &to) const {
	if (!copied.is_empty()) {
		to.add_copied(copied, copy_delta);
	}
	if (!changed.is_empty()) {
		to.add_changed(changed);
	}
}

