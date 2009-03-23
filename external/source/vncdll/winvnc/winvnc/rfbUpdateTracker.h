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

#ifndef __RFB_UPDATETRACKER_INCLUDED__
#define __RFB_UPDATETRACKER_INCLUDED__

#include "rfbRect.h"
#include "rfbRegion.h"

namespace rfb {

	struct UpdateInfo {
		RectVector copied;
		Point copy_delta;
		RectVector changed;
	};

	class UpdateTracker {
	public:
		UpdateTracker() {};
		virtual ~UpdateTracker() {};

		virtual void add_changed(const Region2D &region) = 0;
		virtual void add_copied(const Region2D &dest, const Point &delta) = 0;
	};

	class ClippedUpdateTracker : public UpdateTracker {
	public:
		ClippedUpdateTracker(UpdateTracker &child_) : child(child_) {};
		ClippedUpdateTracker(UpdateTracker &child_,
			const Region2D &cliprgn_) : child(child_), cliprgn(cliprgn_) {};
		virtual ~ClippedUpdateTracker() {};

		virtual void set_clip_region(const Region2D cliprgn_) {cliprgn = cliprgn_;};

		virtual void add_changed(const Region2D &region);
		virtual void add_copied(const Region2D &dest, const Point &delta);
	protected:
		UpdateTracker &child;
		Region2D cliprgn;
	};

	class SimpleUpdateTracker : public UpdateTracker {
	public:
		SimpleUpdateTracker(bool use_copyrect=false);
		virtual ~SimpleUpdateTracker();

		virtual void enable_copyrect(bool enable) {copy_enabled=enable;};

		virtual void add_changed(const Region2D &region);
		virtual void add_copied(const Region2D &dest, const Point &delta);

		// Fill the supplied UpdateInfo structure with update information
		// Also removes the updates that are returned from the update tracker
		virtual void flush_update(UpdateInfo &info, const Region2D &cliprgn);
		virtual void flush_update(UpdateTracker &info, const Region2D &cliprgn);

		// Pass the current updates to the supplied tracker
		// Does not affect internal state of this tracker
		virtual void get_update(UpdateInfo &to) const;
		virtual void get_update(UpdateTracker &to) const;

		// Get the changed/copied regions
		virtual const Region2D& get_changed_region() const {return changed;};
		virtual const Region2D& get_copied_region() const {return copied;};

		virtual bool is_empty() const {return changed.is_empty() && copied.is_empty();};

		virtual void clear() {changed.clear(); copied.clear();};
	protected:
		Region2D changed;
		Region2D copied;
		Point copy_delta;
		bool copy_enabled;
	};

};

#endif __RFB_UPDATETRACKER_INCLUDED__
