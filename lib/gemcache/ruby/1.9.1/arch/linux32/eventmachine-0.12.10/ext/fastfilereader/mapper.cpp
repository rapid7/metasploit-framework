/*****************************************************************************

$Id: mapper.cpp 4527 2007-07-04 10:21:34Z francis $

File:     mapper.cpp
Date:     02Jul07

Copyright (C) 2007 by Francis Cianfrocca. All Rights Reserved.
Gmail: garbagecat10

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/


//////////////////////////////////////////////////////////////////////
// UNIX implementation
//////////////////////////////////////////////////////////////////////


#ifdef OS_UNIX

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include <iostream>
#include "unistd.h"
#include <string>
#include <cstring>
#include <stdexcept>
using namespace std;

#include "mapper.h"

/******************
Mapper_t::Mapper_t
******************/

Mapper_t::Mapper_t (const string &filename)
{
	/* We ASSUME we can open the file.
	 * (More precisely, we assume someone else checked before we got here.)
	 */

	Fd = open (filename.c_str(), O_RDONLY);
	if (Fd < 0)
		throw runtime_error (strerror (errno));

	struct stat st;
	if (fstat (Fd, &st))
		throw runtime_error (strerror (errno));
	FileSize = st.st_size;

	#ifdef OS_WIN32
	MapPoint = (char*) mmap (0, FileSize, PROT_READ, MAP_SHARED, Fd, 0);
	#else
	MapPoint = (const char*) mmap (0, FileSize, PROT_READ, MAP_SHARED, Fd, 0);
	#endif
	if (MapPoint == MAP_FAILED)
		throw runtime_error (strerror (errno));
}


/*******************
Mapper_t::~Mapper_t
*******************/

Mapper_t::~Mapper_t()
{
	Close();
}


/***************
Mapper_t::Close
***************/

void Mapper_t::Close()
{
	// Can be called multiple times.
	// Calls to GetChunk are invalid after a call to Close.
	if (MapPoint) {
		#ifdef OS_SOLARIS8
		munmap ((char*)MapPoint, FileSize);
		#else
		munmap ((void*)MapPoint, FileSize);
		#endif
		MapPoint = NULL;
	}
	if (Fd >= 0) {
		close (Fd);
		Fd = -1;
	}
}

/******************
Mapper_t::GetChunk
******************/

const char *Mapper_t::GetChunk (unsigned start)
{
	return MapPoint + start;
}



#endif // OS_UNIX


//////////////////////////////////////////////////////////////////////
// WINDOWS implementation
//////////////////////////////////////////////////////////////////////

#ifdef OS_WIN32

#include <windows.h>

#include <iostream>
#include <string>
#include <stdexcept>
using namespace std;

#include "mapper.h"

/******************
Mapper_t::Mapper_t
******************/

Mapper_t::Mapper_t (const string &filename)
{
	/* We ASSUME we can open the file.
	 * (More precisely, we assume someone else checked before we got here.)
	 */

	hFile = INVALID_HANDLE_VALUE;
	hMapping = NULL;
	MapPoint = NULL;
	FileSize = 0;

	hFile = CreateFile (filename.c_str(), GENERIC_READ|GENERIC_WRITE, FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		throw runtime_error ("File not found");

	BY_HANDLE_FILE_INFORMATION i;
	if (GetFileInformationByHandle (hFile, &i))
		FileSize = i.nFileSizeLow;

	hMapping = CreateFileMapping (hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (!hMapping)
		throw runtime_error ("File not mapped");

	#ifdef OS_WIN32
	MapPoint = (char*) MapViewOfFile (hMapping, FILE_MAP_WRITE, 0, 0, 0);
	#else
	MapPoint = (const char*) MapViewOfFile (hMapping, FILE_MAP_WRITE, 0, 0, 0);
	#endif
	if (!MapPoint)
		throw runtime_error ("Mappoint not read");
}


/*******************
Mapper_t::~Mapper_t
*******************/

Mapper_t::~Mapper_t()
{
	Close();
}

/***************
Mapper_t::Close
***************/

void Mapper_t::Close()
{
	// Can be called multiple times.
	// Calls to GetChunk are invalid after a call to Close.
	if (MapPoint) {
		UnmapViewOfFile (MapPoint);
		MapPoint = NULL;
	}
	if (hMapping != NULL) {
		CloseHandle (hMapping);
		hMapping = NULL;
	}
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle (hFile);
		hMapping = INVALID_HANDLE_VALUE;
	}
}


/******************
Mapper_t::GetChunk
******************/

const char *Mapper_t::GetChunk (unsigned start)
{
	return MapPoint + start;
}



#endif // OS_WINDOWS
