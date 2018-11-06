/*****************************************************************************

$Id: mapper.h 4529 2007-07-04 11:32:22Z francis $

File:     mapper.h
Date:     02Jul07

Copyright (C) 2007 by Francis Cianfrocca. All Rights Reserved.
Gmail: garbagecat10

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/


#ifndef __Mapper__H_
#define __Mapper__H_


/**************
class Mapper_t
**************/

class Mapper_t
{
	public:
		Mapper_t (const std::string&);
		virtual ~Mapper_t();

		const char *GetChunk (unsigned);
		void Close();
		size_t GetFileSize() {return FileSize;}

	private:
		size_t FileSize;

	#ifdef OS_UNIX
	private:
		int Fd;
		const char *MapPoint;
	#endif // OS_UNIX

	#ifdef OS_WIN32
	private:
		HANDLE hFile;
		HANDLE hMapping;
		char *MapPoint;
	#endif // OS_WIN32

};


#endif // __Mapper__H_

