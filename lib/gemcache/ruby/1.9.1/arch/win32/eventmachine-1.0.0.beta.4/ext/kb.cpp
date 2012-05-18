/*****************************************************************************

$Id$

File:     kb.cpp
Date:     24Aug07

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/

#include "project.h"


/**************************************
KeyboardDescriptor::KeyboardDescriptor
**************************************/

KeyboardDescriptor::KeyboardDescriptor (EventMachine_t *parent_em):
	EventableDescriptor (0, parent_em),
	bReadAttemptedAfterClose (false)
{
	#ifdef HAVE_EPOLL
	EpollEvent.events = EPOLLIN;
	#endif
	#ifdef HAVE_KQUEUE
	MyEventMachine->ArmKqueueReader (this);
	#endif
}


/***************************************
KeyboardDescriptor::~KeyboardDescriptor
***************************************/

KeyboardDescriptor::~KeyboardDescriptor()
{
}


/*************************
KeyboardDescriptor::Write
*************************/

void KeyboardDescriptor::Write()
{
	// Why are we here?
	throw std::runtime_error ("bad code path in keyboard handler");
}


/*****************************
KeyboardDescriptor::Heartbeat
*****************************/

void KeyboardDescriptor::Heartbeat()
{
	// no-op
}


/************************
KeyboardDescriptor::Read
************************/

void KeyboardDescriptor::Read()
{
	char c;
	read (GetSocket(), &c, 1);
	_GenericInboundDispatch(&c, 1);
}
