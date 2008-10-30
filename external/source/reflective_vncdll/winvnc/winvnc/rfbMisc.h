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

#ifndef __RFB_MISC_INCLUDED__
#define __RFB_MISC_INCLUDED__

// Some platforms (e.g. Windows) include max() and min() functions
// in their standard headers.
// These macros are pdefined only when standard equivalents cannot
// be found.

#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

#ifdef WIN32

// WIN32-ONLY PROFILING CODE
//
// CpuTime and CpuTimer provide a simple way to profile particular
// sections of code
//
// Use one CpuTime object per task to be profiled.  CpuTime instances
// maintain a cumulative total of time spent in user and kernel space
// by threads.
// When a CpuTime object is created, a label must be specified to
// identify the task being profiled.
// When the object is destroyed, it will print debugging information
// containing the user and kernel times accumulated.
//
// Place a CpuTimer object in each section of code which is to be
// profiled.  When the object is created, it snapshots the current
// kernel and user times and stores them.  These are used when the
// object is destroyed to establish how much time has elapsed in the
// intervening period.  The accumulated time is then added to the
// associated CpuTime object.
//
// This code works only on platforms providing __int64

namespace rfb {

	class CpuTime {
	public:
		CpuTime(const char *name)
			: timer_name(strdup(name)),
			  kernel_time(0), user_time(0), max_user_time(0), iterations(0) {}
		~CpuTime() {
			//vnclog.Print(0, "timer %s : %I64ums (krnl), %I64ums (user), %I64uus (user-max) (%I64u its)\n",
			//	timer_name, kernel_time/10000, user_time/10000, max_user_time/10,
			//	iterations);
			delete [] timer_name;
		}
		char* timer_name;
		__int64 kernel_time;
		__int64 user_time;
		__int64 iterations;
		__int64 max_user_time;
	};

	class CpuTimer {
	public:
		inline CpuTimer(CpuTime &ct) : cputime(ct) {
			FILETIME create_time, end_time;
			if (!GetThreadTimes(GetCurrentThread(),
				&create_time, &end_time,
				(LPFILETIME)&start_kernel_time,
				(LPFILETIME)&start_user_time)) {
				abort();
			}
		}
		inline ~CpuTimer() {
			FILETIME create_time, end_time;
			__int64 end_kernel_time, end_user_time;
			if (!GetThreadTimes(GetCurrentThread(),
				&create_time, &end_time,
				(LPFILETIME)&end_kernel_time,
				(LPFILETIME)&end_user_time)) {
				abort();
			}
			cputime.kernel_time += end_kernel_time - start_kernel_time;
			cputime.user_time += end_user_time - start_user_time;
			if (end_user_time - start_user_time > cputime.max_user_time) {
				cputime.max_user_time = end_user_time - start_user_time;
			}
			cputime.iterations++;
		}
	private:
		CpuTime& cputime;
		__int64 start_kernel_time;
		__int64 start_user_time;
	};
};

#endif

#endif // __RFB_MISC_INCLUDED__


