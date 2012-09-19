/*****************************************************************************

$Id$

File:     page.h
Date:     30Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/


#ifndef __PageManager__H_
#define __PageManager__H_


/**************
class PageList
**************/

class PageList
{
	struct Page {
		Page (const char *b, size_t s): Buffer(b), Size(s) {}
		const char *Buffer;
		size_t Size;
	};

	public:
		PageList();
		virtual ~PageList();

		void Push (const char*, int);
		bool HasPages();
		void Front (const char**, int*);
		void PopFront();

	private:
		deque<Page> Pages;
};


#endif // __PageManager__H_
