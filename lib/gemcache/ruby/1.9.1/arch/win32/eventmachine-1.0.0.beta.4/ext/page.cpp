/*****************************************************************************

$Id$

File:     page.cpp
Date:     30Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/


#include "project.h"


/******************
PageList::PageList
******************/

PageList::PageList()
{
}


/*******************
PageList::~PageList
*******************/

PageList::~PageList()
{
	while (HasPages())
		PopFront();
}


/***************
PageList::Front
***************/

void PageList::Front (const char **page, int *length)
{
	assert (page && length);

	if (HasPages()) {
		Page p = Pages.front();
		*page = p.Buffer;
		*length = p.Size;
	}
	else {
		*page = NULL;
		*length = 0;
	}
}


/******************
PageList::PopFront
******************/

void PageList::PopFront()
{
	if (HasPages()) {
		Page p = Pages.front();
		Pages.pop_front();
		if (p.Buffer)
			free ((void*)p.Buffer);
	}
}


/******************
PageList::HasPages
******************/

bool PageList::HasPages()
{
	return (Pages.size() > 0) ? true : false;
}


/**************
PageList::Push
**************/

void PageList::Push (const char *buf, int size)
{
	if (buf && (size > 0)) {
		char *copy = (char*) malloc (size);
		if (!copy)
			throw runtime_error ("no memory in pagelist");
		memcpy (copy, buf, size);
		Pages.push_back (Page (copy, size));
	}
}





