/*****************************************************************************

$Id$

File:     files.h
Date:     26Aug06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/


#ifndef __FileStreamDescriptor__H_
#define __FileStreamDescriptor__H_



/**************************
class FileStreamDescriptor
**************************/

class FileStreamDescriptor: public EventableDescriptor
{
	public:
		FileStreamDescriptor (int, EventMachine_t*);
		virtual ~FileStreamDescriptor();

		virtual void Read();
		virtual void Write();
		virtual void Heartbeat();

		virtual bool SelectForRead();
		virtual bool SelectForWrite();

		// Do we have any data to write? This is used by ShouldDelete.
		virtual int GetOutboundDataSize() {return OutboundDataSize;}

	protected:
		struct OutboundPage {
			OutboundPage (const char *b, int l, int o=0): Buffer(b), Length(l), Offset(o) {}
			void Free() {if (Buffer) free ((char*)Buffer); }
			const char *Buffer;
			int Length;
			int Offset;
		};

	protected:
		deque<OutboundPage> OutboundPages;
		int OutboundDataSize;

	private:

};


#endif // __FileStreamDescriptor__H_

