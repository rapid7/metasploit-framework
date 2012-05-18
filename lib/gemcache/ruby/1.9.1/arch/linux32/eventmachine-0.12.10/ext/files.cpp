/*****************************************************************************

$Id$

File:     files.cpp
Date:     26Aug06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/

#include "project.h"


/******************************************
FileStreamDescriptor::FileStreamDescriptor
******************************************/

FileStreamDescriptor::FileStreamDescriptor (int fd, EventMachine_t *em):
	EventableDescriptor (fd, em),
	OutboundDataSize (0)
{
cerr << "#####";
}


/*******************************************
FileStreamDescriptor::~FileStreamDescriptor
*******************************************/

FileStreamDescriptor::~FileStreamDescriptor()
{
	// Run down any stranded outbound data.
	for (size_t i=0; i < OutboundPages.size(); i++)
		OutboundPages[i].Free();
}


/**************************
FileStreamDescriptor::Read
**************************/

void FileStreamDescriptor::Read()
{
}

/***************************
FileStreamDescriptor::Write
***************************/

void FileStreamDescriptor::Write()
{
}


/*******************************
FileStreamDescriptor::Heartbeat
*******************************/

void FileStreamDescriptor::Heartbeat()
{
}


/***********************************
FileStreamDescriptor::SelectForRead
***********************************/

bool FileStreamDescriptor::SelectForRead()
{
  cerr << "R?";
  return false;
}


/************************************
FileStreamDescriptor::SelectForWrite
************************************/

bool FileStreamDescriptor::SelectForWrite()
{
  cerr << "W?";
  return false;
}


