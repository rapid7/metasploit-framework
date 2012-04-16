/*****************************************************************************

$Id$

File:     emwin.h
Date:     05May06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/


// THIS ENTIRE FILE IS FOR WINDOWS BUILDS ONLY.
// INCOMPLETE AND DISABLED FOR NOW.
#ifdef xOS_WIN32

#ifndef __EventMachine__H_
#define __EventMachine__H_


extern time_t gCurrentLoopTime;

class EventableDescriptor;


/********************
class EventMachine_t
********************/

class EventMachine_t
{
	public:
		EventMachine_t (void(*event_callback)(const char*, int, const char*, int));
		virtual ~EventMachine_t();

		void Run();
		void ScheduleHalt();
		const char *InstallOneshotTimer (int);
		const char *ConnectToServer (const char *, int);
		const char *CreateTcpServer (const char *, int);
		const char *OpenDatagramSocket (const char *, int);

		void Add (EventableDescriptor*);

	public:
		enum { // Event names
			TIMER_FIRED = 100,
			CONNECTION_READ = 101,
			CONNECTION_UNBOUND = 102,
			CONNECTION_ACCEPTED = 103,
			CONNECTION_COMPLETED = 104,
			LOOPBREAK_SIGNAL = 105
		};

	private:
		HANDLE Iocp;

	private:
		bool _RunOnce();
		bool _RunTimers();
		void _AddNewDescriptors();

	private:
		enum {
			MaxOutstandingTimers = 40,
			HeartbeatInterval = 2
		};
		void (*EventCallback)(const char*, int, const char*, int);

		class Timer_t: public Bindable_t {
		};

		multimap<time_t, Timer_t> Timers;
		vector<EventableDescriptor*> Descriptors;
		vector<EventableDescriptor*> NewDescriptors;

		time_t NextHeartbeatTime;
};




#endif // __EventMachine__H_

#endif // OS_WIN32

