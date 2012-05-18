/*****************************************************************************

$Id$

File:     emwin.cpp
Date:     05May06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/


// THIS ENTIRE FILE IS FOR WINDOWS BUILDS ONLY
// INCOMPLETE AND DISABLED FOR NOW.
#ifdef xOS_WIN32

#include "project.h"


// Keep a global variable floating around
// with the current loop time as set by the Event Machine.
// This avoids the need for frequent expensive calls to time(NULL);
time_t gCurrentLoopTime;


/******************************
EventMachine_t::EventMachine_t
******************************/

EventMachine_t::EventMachine_t (void (*event_callback)(const char*, int, const char*, int)):
	EventCallback (event_callback),
	NextHeartbeatTime (0)
{
	gTerminateSignalReceived = false;
	Iocp = NULL;
}


/*******************************
EventMachine_t::~EventMachine_t
*******************************/

EventMachine_t::~EventMachine_t()
{
	cerr << "EM __dt\n";
	if (Iocp)
		CloseHandle (Iocp);
}


/****************************
EventMachine_t::ScheduleHalt
****************************/

void EventMachine_t::ScheduleHalt()
{
  /* This is how we stop the machine.
   * This can be called by clients. Signal handlers will probably
   * set the global flag.
   * For now this means there can only be one EventMachine ever running at a time.
   */
	gTerminateSignalReceived = true;
}



/*******************
EventMachine_t::Run
*******************/

void EventMachine_t::Run()
{
	HookControlC (true);

	Iocp = CreateIoCompletionPort (INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (Iocp == NULL)
		throw std::runtime_error ("no completion port");


	DWORD nBytes, nCompletionKey;
	LPOVERLAPPED Overlapped;

	do {
		gCurrentLoopTime = time(NULL);
		// Have some kind of strategy that will dequeue maybe up to 10 completions 
		// without running the timers as long as they are available immediately.
		// Otherwise in a busy server we're calling them every time through the loop.
		if (!_RunTimers())
			break;
		if (GetQueuedCompletionStatus (Iocp, &nBytes, &nCompletionKey, &Overlapped, 1000)) {
		}
		cerr << "+";
	} while (!gTerminateSignalReceived);


	/*
	while (true) {
		gCurrentLoopTime = time(NULL);
		if (!_RunTimers())
			break;
		_AddNewDescriptors();
		if (!_RunOnce())
			break;
		if (gTerminateSignalReceived)
			break;
	}
	*/

	HookControlC (false);
}


/**************************
EventMachine_t::_RunTimers
**************************/

bool EventMachine_t::_RunTimers()
{
	// These are caller-defined timer handlers.
	// Return T/F to indicate whether we should continue the main loop.
	// We rely on the fact that multimaps sort by their keys to avoid
	// inspecting the whole list every time we come here.
	// Just keep inspecting and processing the list head until we hit
	// one that hasn't expired yet.

	while (true) {
		multimap<time_t,Timer_t>::iterator i = Timers.begin();
		if (i == Timers.end())
			break;
		if (i->first > gCurrentLoopTime)
			break;
		if (EventCallback)
			(*EventCallback) (NULL, EM_TIMER_FIRED, NULL, i->second.GetBinding());
		Timers.erase (i);
	}
	return true;
}


/***********************************
EventMachine_t::InstallOneshotTimer
***********************************/

const char *EventMachine_t::InstallOneshotTimer (int seconds)
{
	if (Timers.size() > MaxOutstandingTimers)
		return false;
	// Don't use the global loop-time variable here, because we might
	// get called before the main event machine is running.

	Timer_t t;
	Timers.insert (make_pair (time(NULL) + seconds, t));
	return t.GetBinding();
}


/**********************************
EventMachine_t::OpenDatagramSocket
**********************************/

const char *EventMachine_t::OpenDatagramSocket (const char *address, int port)
{
	cerr << "OPEN DATAGRAM SOCKET\n";
	return "Unimplemented";
}


/*******************************
EventMachine_t::CreateTcpServer
*******************************/

const char *EventMachine_t::CreateTcpServer (const char *server, int port)
{
	/* Create a TCP-acceptor (server) socket and add it to the event machine.
	 * Return the binding of the new acceptor to the caller.
	 * This binding will be referenced when the new acceptor sends events
	 * to indicate accepted connections.
	 */

	const char *output_binding = NULL;

	struct sockaddr_in sin;

	SOCKET sd_accept = socket (AF_INET, SOCK_STREAM, 0);
	if (sd_accept == INVALID_SOCKET) {
		goto fail;
	}

	memset (&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons (port);

	if (server && *server) {
		sin.sin_addr.s_addr = inet_addr (server);
		if (sin.sin_addr.s_addr == INADDR_NONE) {
			hostent *hp = gethostbyname (server);
			if (hp == NULL) {
				//__warning ("hostname not resolved: ", server);
				goto fail;
			}
			sin.sin_addr.s_addr = ((in_addr*)(hp->h_addr))->s_addr;
		}
	}


	// No need to set reuseaddr on Windows.


	if (bind (sd_accept, (struct sockaddr*)&sin, sizeof(sin))) {
		//__warning ("binding failed");
		goto fail;
	}

	if (listen (sd_accept, 100)) {
		//__warning ("listen failed");
		goto fail;
	}

	{ // Looking good.
		AcceptorDescriptor *ad = new AcceptorDescriptor (this, sd_accept);
		if (!ad)
			throw std::runtime_error ("unable to allocate acceptor");
		Add (ad);
		output_binding = ad->GetBinding();

		CreateIoCompletionPort ((HANDLE)sd_accept, Iocp, NULL, 0);
		SOCKET sd = socket (AF_INET, SOCK_STREAM, 0);
		CreateIoCompletionPort ((HANDLE)sd, Iocp, NULL, 0);
		AcceptEx (sd_accept, sd, 
	}

	return output_binding;

	fail:
	if (sd_accept != INVALID_SOCKET)
		closesocket (sd_accept);
	return NULL;
}


/*******************************
EventMachine_t::ConnectToServer
*******************************/

const char *EventMachine_t::ConnectToServer (const char *server, int port)
{
	if (!server || !*server || !port)
		return NULL;

	sockaddr_in pin;
	unsigned long HostAddr;

	HostAddr = inet_addr (server);
	if (HostAddr == INADDR_NONE) {
		hostent *hp = gethostbyname (server);
		if (!hp)
			return NULL;
		HostAddr = ((in_addr*)(hp->h_addr))->s_addr;
	}

	memset (&pin, 0, sizeof(pin));
	pin.sin_family = AF_INET;
	pin.sin_addr.s_addr = HostAddr;
	pin.sin_port = htons (port);

	int sd = socket (AF_INET, SOCK_STREAM, 0);
	if (sd == INVALID_SOCKET)
		return NULL;


	LPOVERLAPPED olap = (LPOVERLAPPED) calloc (1, sizeof (OVERLAPPED));
	cerr << "I'm dying now\n";
	throw runtime_error ("UNIMPLEMENTED!!!\n");

}



/*******************
EventMachine_t::Add
*******************/

void EventMachine_t::Add (EventableDescriptor *ed)
{
	cerr << "ADD\n";
}



#endif // OS_WIN32

