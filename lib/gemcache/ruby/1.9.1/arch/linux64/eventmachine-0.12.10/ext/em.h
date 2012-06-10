/*****************************************************************************

$Id$

File:     em.h
Date:     06Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/



#ifdef OS_WIN32
#include "emwin.h"
#endif


// THIS ENTIRE FILE WILL EVENTUALLY BE FOR UNIX BUILDS ONLY.
//#ifdef OS_UNIX

#ifndef __EventMachine__H_
#define __EventMachine__H_

#ifdef BUILD_FOR_RUBY
  #include <ruby.h>
  #define EmSelect rb_thread_select

  #if defined(HAVE_RBTRAP)
    #include <rubysig.h>
  #elif defined(HAVE_RB_THREAD_CHECK_INTS)
    extern "C" {
      void rb_enable_interrupt(void);
      void rb_disable_interrupt(void);
    }

    #define TRAP_BEG rb_enable_interrupt()
    #define TRAP_END do { rb_disable_interrupt(); rb_thread_check_ints(); } while(0)
  #else
    #define TRAP_BEG
    #define TRAP_END
  #endif

  // 1.9.0 compat
  #ifndef RUBY_UBF_IO
    #define RUBY_UBF_IO RB_UBF_DFL
  #endif
#else
  #define EmSelect select
#endif


#ifdef OS_UNIX
typedef long long Int64;
#endif
#ifdef OS_WIN32
typedef __int64 Int64;
#endif

extern Int64 gCurrentLoopTime;

class EventableDescriptor;
class InotifyDescriptor;


/********************
class EventMachine_t
********************/

class EventMachine_t
{
	public:
		static int GetMaxTimerCount();
		static void SetMaxTimerCount (int);

	public:
		EventMachine_t (void(*event_callback)(const unsigned long, int, const char*, const unsigned long));
		virtual ~EventMachine_t();

		void Run();
		void ScheduleHalt();
		void SignalLoopBreaker();
		const unsigned long InstallOneshotTimer (int);
		const unsigned long ConnectToServer (const char *, int, const char *, int);
		const unsigned long ConnectToUnixServer (const char *);

		const unsigned long CreateTcpServer (const char *, int);
		const unsigned long OpenDatagramSocket (const char *, int);
		const unsigned long CreateUnixDomainServer (const char*);
		const unsigned long _OpenFileForWriting (const char*);
		const unsigned long OpenKeyboard();
		//const char *Popen (const char*, const char*);
		const unsigned long Socketpair (char* const*);

		void Add (EventableDescriptor*);
		void Modify (EventableDescriptor*);

		const unsigned long AttachFD (int, bool);
		int DetachFD (EventableDescriptor*);

		void ArmKqueueWriter (EventableDescriptor*);
		void ArmKqueueReader (EventableDescriptor*);

		void SetTimerQuantum (int);
		static void SetuidString (const char*);
		static int SetRlimitNofile (int);

		pid_t SubprocessPid;
		int SubprocessExitStatus;

		int GetConnectionCount();
		float GetHeartbeatInterval();
		int SetHeartbeatInterval(float);

		const unsigned long WatchFile (const char*);
		void UnwatchFile (int);
		void UnwatchFile (const unsigned long);

		#ifdef HAVE_KQUEUE
		void _HandleKqueueFileEvent (struct kevent*);
		void _RegisterKqueueFileEvent(int);
		#endif

		const unsigned long WatchPid (int);
		void UnwatchPid (int);
		void UnwatchPid (const unsigned long);

		#ifdef HAVE_KQUEUE
		void _HandleKqueuePidEvent (struct kevent*);
		#endif

		// Temporary:
		void _UseEpoll();
		void _UseKqueue();

		bool UsingKqueue() { return bKqueue; }
		bool UsingEpoll() { return bEpoll; }

	private:
		bool _RunOnce();
		bool _RunTimers();
		void _UpdateTime();
		void _AddNewDescriptors();
		void _ModifyDescriptors();
		void _InitializeLoopBreaker();

		bool _RunSelectOnce();
		bool _RunEpollOnce();
		bool _RunKqueueOnce();

		void _ModifyEpollEvent (EventableDescriptor*);

	public:
		void _ReadLoopBreaker();
		void _ReadInotifyEvents();

	private:
		enum {
			MaxEpollDescriptors = 64*1024,
			MaxEvents = 4096
		};
		int HeartbeatInterval;
		void (*EventCallback)(const unsigned long, int, const char*, const unsigned long);

		class Timer_t: public Bindable_t {
		};

		multimap<Int64, Timer_t> Timers;
		map<int, Bindable_t*> Files;
		map<int, Bindable_t*> Pids;
		vector<EventableDescriptor*> Descriptors;
		vector<EventableDescriptor*> NewDescriptors;
		set<EventableDescriptor*> ModifiedDescriptors;

		Int64 NextHeartbeatTime;

		int LoopBreakerReader;
		int LoopBreakerWriter;
		#ifdef OS_WIN32
		struct sockaddr_in LoopBreakerTarget;
		#endif

		timeval Quantum;

	private:
		bool bEpoll;
		int epfd; // Epoll file-descriptor
		#ifdef HAVE_EPOLL
		struct epoll_event epoll_events [MaxEvents];
		#endif

		bool bKqueue;
		int kqfd; // Kqueue file-descriptor
		#ifdef HAVE_KQUEUE
		struct kevent Karray [MaxEvents];
		#endif

		InotifyDescriptor *inotify; // pollable descriptor for our inotify instance
};


/*******************
struct SelectData_t
*******************/

struct SelectData_t
{
	SelectData_t();

	int _Select();

	int maxsocket;
	fd_set fdreads;
	fd_set fdwrites;
	fd_set fderrors;
	timeval tv;
	int nSockets;
};



#endif // __EventMachine__H_

//#endif // OS_UNIX
