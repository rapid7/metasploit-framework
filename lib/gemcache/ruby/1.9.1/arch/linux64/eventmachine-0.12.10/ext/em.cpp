/*****************************************************************************

$Id$

File:     em.cpp
Date:     06Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/

// THIS ENTIRE FILE WILL EVENTUALLY BE FOR UNIX BUILDS ONLY.
//#ifdef OS_UNIX


#include "project.h"

// Keep a global variable floating around
// with the current loop time as set by the Event Machine.
// This avoids the need for frequent expensive calls to time(NULL);
Int64 gCurrentLoopTime;

#ifdef OS_WIN32
unsigned gTickCountTickover;
unsigned gLastTickCount;
#endif


/* The numer of max outstanding timers was once a const enum defined in em.h.
 * Now we define it here so that users can change its value if necessary.
 */
static unsigned int MaxOutstandingTimers = 10000;


/* Internal helper to convert strings to internet addresses. IPv6-aware.
 * Not reentrant or threadsafe, optimized for speed.
 */
static struct sockaddr *name2address (const char *server, int port, int *family, int *bind_size);

/***************************************
STATIC EventMachine_t::GetMaxTimerCount
***************************************/

int EventMachine_t::GetMaxTimerCount()
{
	return MaxOutstandingTimers;
}


/***************************************
STATIC EventMachine_t::SetMaxTimerCount
***************************************/

void EventMachine_t::SetMaxTimerCount (int count)
{
	/* Allow a user to increase the maximum number of outstanding timers.
	 * If this gets "too high" (a metric that is of course platform dependent),
	 * bad things will happen like performance problems and possible overuse
	 * of memory.
	 * The actual timer mechanism is very efficient so it's hard to know what
	 * the practical max, but 100,000 shouldn't be too problematical.
	 */
	if (count < 100)
		count = 100;
	MaxOutstandingTimers = count;
}



/******************************
EventMachine_t::EventMachine_t
******************************/

EventMachine_t::EventMachine_t (void (*event_callback)(const unsigned long, int, const char*, const unsigned long)):
	HeartbeatInterval(2000000),
	EventCallback (event_callback),
	NextHeartbeatTime (0),
	LoopBreakerReader (-1),
	LoopBreakerWriter (-1),
	bEpoll (false),
	epfd (-1),
	bKqueue (false),
	kqfd (-1),
	inotify (NULL)
{
	// Default time-slice is just smaller than one hundred mills.
	Quantum.tv_sec = 0;
	Quantum.tv_usec = 90000;

	gTerminateSignalReceived = false;
	// Make sure the current loop time is sane, in case we do any initializations of
	// objects before we start running.
	_UpdateTime();

	/* We initialize the network library here (only on Windows of course)
	 * and initialize "loop breakers." Our destructor also does some network-level
	 * cleanup. There's thus an implicit assumption that any given instance of EventMachine_t
	 * will only call ::Run once. Is that a good assumption? Should we move some of these
	 * inits and de-inits into ::Run?
	 */
	#ifdef OS_WIN32
	WSADATA w;
	WSAStartup (MAKEWORD (1, 1), &w);
	#endif

	_InitializeLoopBreaker();
}


/*******************************
EventMachine_t::~EventMachine_t
*******************************/

EventMachine_t::~EventMachine_t()
{
	// Run down descriptors
	size_t i;
	for (i = 0; i < NewDescriptors.size(); i++)
		delete NewDescriptors[i];
	for (i = 0; i < Descriptors.size(); i++)
		delete Descriptors[i];

	close (LoopBreakerReader);
	close (LoopBreakerWriter);

	// Remove any file watch descriptors
	while(!Files.empty()) {
		map<int, Bindable_t*>::iterator f = Files.begin();
		UnwatchFile (f->first);
	}

	if (epfd != -1)
		close (epfd);
	if (kqfd != -1)
		close (kqfd);
}


/*************************
EventMachine_t::_UseEpoll
*************************/

void EventMachine_t::_UseEpoll()
{
	/* Temporary.
	 * Use an internal flag to switch in epoll-based functionality until we determine
	 * how it should be integrated properly and the extent of the required changes.
	 * A permanent solution needs to allow the integration of additional technologies,
	 * like kqueue and Solaris's events.
	 */

	#ifdef HAVE_EPOLL
	bEpoll = true;
	#endif
}

/**************************
EventMachine_t::_UseKqueue
**************************/

void EventMachine_t::_UseKqueue()
{
	/* Temporary.
	 * See comments under _UseEpoll.
	 */

	#ifdef HAVE_KQUEUE
	bKqueue = true;
	#endif
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
   *
   * IMPORTANT: keep this light, fast, and async-safe. Don't do anything frisky in here,
   * because it may be called from signal handlers invoked from code that we don't
   * control. At this writing (20Sep06), EM does NOT install any signal handlers of
   * its own.
   *
   * We need a FAQ. And one of the questions is: how do I stop EM when Ctrl-C happens?
   * The answer is to call evma_stop_machine, which calls here, from a SIGINT handler.
   */
	gTerminateSignalReceived = true;
}



/*******************************
EventMachine_t::SetTimerQuantum
*******************************/

void EventMachine_t::SetTimerQuantum (int interval)
{
	/* We get a timer-quantum expressed in milliseconds.
	 * Don't set a quantum smaller than 5 or larger than 2500.
	 */

	if ((interval < 5) || (interval > 2500))
		throw std::runtime_error ("invalid timer-quantum");

	Quantum.tv_sec = interval / 1000;
	Quantum.tv_usec = (interval % 1000) * 1000;
}


/*************************************
(STATIC) EventMachine_t::SetuidString
*************************************/

void EventMachine_t::SetuidString (const char *username)
{
    /* This method takes a caller-supplied username and tries to setuid
     * to that user. There is no meaningful implementation (and no error)
     * on Windows. On Unix, a failure to setuid the caller-supplied string
     * causes a fatal abort, because presumably the program is calling here
     * in order to fulfill a security requirement. If we fail silently,
     * the user may continue to run with too much privilege.
     *
     * TODO, we need to decide on and document a way of generating C++ level errors
     * that can be wrapped in documented Ruby exceptions, so users can catch
     * and handle them. And distinguish it from errors that we WON'T let the Ruby
     * user catch (like security-violations and resource-overallocation).
     * A setuid failure here would be in the latter category.
     */

    #ifdef OS_UNIX
    if (!username || !*username)
	throw std::runtime_error ("setuid_string failed: no username specified");

    struct passwd *p = getpwnam (username);
    if (!p)
	throw std::runtime_error ("setuid_string failed: unknown username");

    if (setuid (p->pw_uid) != 0)
	throw std::runtime_error ("setuid_string failed: no setuid");

    // Success.
    #endif
}


/****************************************
(STATIC) EventMachine_t::SetRlimitNofile
****************************************/

int EventMachine_t::SetRlimitNofile (int nofiles)
{
	#ifdef OS_UNIX
	struct rlimit rlim;
	getrlimit (RLIMIT_NOFILE, &rlim);
	if (nofiles >= 0) {
		rlim.rlim_cur = nofiles;
		if ((unsigned int)nofiles > rlim.rlim_max)
			rlim.rlim_max = nofiles;
		setrlimit (RLIMIT_NOFILE, &rlim);
		// ignore the error return, for now at least.
		// TODO, emit an error message someday when we have proper debug levels.
	}
	getrlimit (RLIMIT_NOFILE, &rlim);
	return rlim.rlim_cur;
	#endif

	#ifdef OS_WIN32
	// No meaningful implementation on Windows.
	return 0;
	#endif
}


/*********************************
EventMachine_t::SignalLoopBreaker
*********************************/

void EventMachine_t::SignalLoopBreaker()
{
	#ifdef OS_UNIX
	write (LoopBreakerWriter, "", 1);
	#endif
	#ifdef OS_WIN32
	sendto (LoopBreakerReader, "", 0, 0, (struct sockaddr*)&(LoopBreakerTarget), sizeof(LoopBreakerTarget));
	#endif
}


/**************************************
EventMachine_t::_InitializeLoopBreaker
**************************************/

void EventMachine_t::_InitializeLoopBreaker()
{
	/* A "loop-breaker" is a socket-descriptor that we can write to in order
	 * to break the main select loop. Primarily useful for things running on
	 * threads other than the main EM thread, so they can trigger processing
	 * of events that arise exogenously to the EM.
	 * Keep the loop-breaker pipe out of the main descriptor set, otherwise
	 * its events will get passed on to user code.
	 */

	#ifdef OS_UNIX
	int fd[2];
	if (pipe (fd))
		throw std::runtime_error ("no loop breaker");

	LoopBreakerWriter = fd[1];
	LoopBreakerReader = fd[0];
	#endif

	#ifdef OS_WIN32
	int sd = socket (AF_INET, SOCK_DGRAM, 0);
	if (sd == INVALID_SOCKET)
		throw std::runtime_error ("no loop breaker socket");
	SetSocketNonblocking (sd);

	memset (&LoopBreakerTarget, 0, sizeof(LoopBreakerTarget));
	LoopBreakerTarget.sin_family = AF_INET;
	LoopBreakerTarget.sin_addr.s_addr = inet_addr ("127.0.0.1");

	srand ((int)time(NULL));
	int i;
	for (i=0; i < 100; i++) {
		int r = (rand() % 10000) + 20000;
		LoopBreakerTarget.sin_port = htons (r);
		if (bind (sd, (struct sockaddr*)&LoopBreakerTarget, sizeof(LoopBreakerTarget)) == 0)
			break;
	}

	if (i == 100)
		throw std::runtime_error ("no loop breaker");
	LoopBreakerReader = sd;
	#endif
}

/***************************
EventMachine_t::_UpdateTime
***************************/

void EventMachine_t::_UpdateTime()
{
	#if defined(OS_UNIX)
	struct timeval tv;
	gettimeofday (&tv, NULL);
	gCurrentLoopTime = (((Int64)(tv.tv_sec)) * 1000000LL) + ((Int64)(tv.tv_usec));

	#elif defined(OS_WIN32)
	unsigned tick = GetTickCount();
	if (tick < gLastTickCount)
		gTickCountTickover += 1;
	gLastTickCount = tick;
	gCurrentLoopTime = ((Int64)gTickCountTickover << 32) + (Int64)tick;

	#else
	gCurrentLoopTime = (Int64)time(NULL) * 1000000LL;
	#endif
}

/*******************
EventMachine_t::Run
*******************/

void EventMachine_t::Run()
{
	#ifdef OS_WIN32
	HookControlC (true);
	#endif

	#ifdef HAVE_EPOLL
	if (bEpoll) {
		epfd = epoll_create (MaxEpollDescriptors);
		if (epfd == -1) {
			char buf[200];
			snprintf (buf, sizeof(buf)-1, "unable to create epoll descriptor: %s", strerror(errno));
			throw std::runtime_error (buf);
		}
		int cloexec = fcntl (epfd, F_GETFD, 0);
		assert (cloexec >= 0);
		cloexec |= FD_CLOEXEC;
		fcntl (epfd, F_SETFD, cloexec);

		assert (LoopBreakerReader >= 0);
		LoopbreakDescriptor *ld = new LoopbreakDescriptor (LoopBreakerReader, this);
		assert (ld);
		Add (ld);
	}
	#endif

	#ifdef HAVE_KQUEUE
	if (bKqueue) {
		kqfd = kqueue();
		if (kqfd == -1) {
			char buf[200];
			snprintf (buf, sizeof(buf)-1, "unable to create kqueue descriptor: %s", strerror(errno));
			throw std::runtime_error (buf);
		}
		// cloexec not needed. By definition, kqueues are not carried across forks.

		assert (LoopBreakerReader >= 0);
		LoopbreakDescriptor *ld = new LoopbreakDescriptor (LoopBreakerReader, this);
		assert (ld);
		Add (ld);
	}
	#endif

	while (true) {
		_UpdateTime();
		if (!_RunTimers())
			break;

		/* _Add must precede _Modify because the same descriptor might
		 * be on both lists during the same pass through the machine,
		 * and to modify a descriptor before adding it would fail.
		 */
		_AddNewDescriptors();
		_ModifyDescriptors();

		if (!_RunOnce())
			break;
		if (gTerminateSignalReceived)
			break;
	}

	#ifdef OS_WIN32
	HookControlC (false);
	#endif
}


/************************
EventMachine_t::_RunOnce
************************/

bool EventMachine_t::_RunOnce()
{
	if (bEpoll)
		return _RunEpollOnce();
	else if (bKqueue)
		return _RunKqueueOnce();
	else
		return _RunSelectOnce();
}



/*****************************
EventMachine_t::_RunEpollOnce
*****************************/

bool EventMachine_t::_RunEpollOnce()
{
	#ifdef HAVE_EPOLL
	assert (epfd != -1);
	int s;

	#ifdef BUILD_FOR_RUBY
	TRAP_BEG;
	#endif
	s = epoll_wait (epfd, epoll_events, MaxEvents, 50);
	#ifdef BUILD_FOR_RUBY
	TRAP_END;
	#endif

	if (s > 0) {
		for (int i=0; i < s; i++) {
			EventableDescriptor *ed = (EventableDescriptor*) epoll_events[i].data.ptr;

			if (ed->IsWatchOnly() && ed->GetSocket() == INVALID_SOCKET)
				continue;

			assert(ed->GetSocket() != INVALID_SOCKET);

			if (epoll_events[i].events & EPOLLIN)
				ed->Read();
			if (epoll_events[i].events & EPOLLOUT)
				ed->Write();
			if (epoll_events[i].events & (EPOLLERR | EPOLLHUP))
				ed->HandleError();
		}
	}
	else if (s < 0) {
		// epoll_wait can fail on error in a handful of ways.
		// If this happens, then wait for a little while to avoid busy-looping.
		// If the error was EINTR, we probably caught SIGCHLD or something,
		// so keep the wait short.
		timeval tv = {0, ((errno == EINTR) ? 5 : 50) * 1000};
		EmSelect (0, NULL, NULL, NULL, &tv);
	}

	{ // cleanup dying sockets
		// vector::pop_back works in constant time.
		// TODO, rip this out and only delete the descriptors we know have died,
		// rather than traversing the whole list.
		//  Modified 05Jan08 per suggestions by Chris Heath. It's possible that
		//  an EventableDescriptor will have a descriptor value of -1. That will
		//  happen if EventableDescriptor::Close was called on it. In that case,
		//  don't call epoll_ctl to remove the socket's filters from the epoll set.
		//  According to the epoll docs, this happens automatically when the
		//  descriptor is closed anyway. This is different from the case where
		//  the socket has already been closed but the descriptor in the ED object
		//  hasn't yet been set to INVALID_SOCKET.
		int i, j;
		int nSockets = Descriptors.size();
		for (i=0, j=0; i < nSockets; i++) {
			EventableDescriptor *ed = Descriptors[i];
			assert (ed);
			if (ed->ShouldDelete()) {
				if (ed->GetSocket() != INVALID_SOCKET) {
					assert (bEpoll); // wouldn't be in this method otherwise.
					assert (epfd != -1);
					int e = epoll_ctl (epfd, EPOLL_CTL_DEL, ed->GetSocket(), ed->GetEpollEvent());
					// ENOENT or EBADF are not errors because the socket may be already closed when we get here.
					if (e && (errno != ENOENT) && (errno != EBADF) && (errno != EPERM)) {
						char buf [200];
						snprintf (buf, sizeof(buf)-1, "unable to delete epoll event: %s", strerror(errno));
						throw std::runtime_error (buf);
					}
				}

				ModifiedDescriptors.erase (ed);
				delete ed;
			}
			else
				Descriptors [j++] = ed;
		}
		while ((size_t)j < Descriptors.size())
			Descriptors.pop_back();

	}

	// TODO, heartbeats.
	// Added 14Sep07, its absence was noted by Brian Candler. But the comment was here, indicated
	// that this got thought about and not done when EPOLL was originally written. Was there a reason
	// not to do it, or was it an oversight? Certainly, running a heartbeat on 50,000 connections every
	// two seconds can get to be a real bear, especially if all we're doing is timing out dead ones.
	// Maybe there's a better way to do this. (Or maybe it's not that expensive after all.)
	//
	{ // dispatch heartbeats
		if (gCurrentLoopTime >= NextHeartbeatTime) {
			NextHeartbeatTime = gCurrentLoopTime + HeartbeatInterval;

			for (int i=0; i < Descriptors.size(); i++) {
				EventableDescriptor *ed = Descriptors[i];
				assert (ed);
				ed->Heartbeat();
			}
		}
	}

	#ifdef BUILD_FOR_RUBY
	if (!rb_thread_alone()) {
		rb_thread_schedule();
	}
	#endif

	return true;
	#else
	throw std::runtime_error ("epoll is not implemented on this platform");
	#endif
}


/******************************
EventMachine_t::_RunKqueueOnce
******************************/

bool EventMachine_t::_RunKqueueOnce()
{
	#ifdef HAVE_KQUEUE
	assert (kqfd != -1);
	struct timespec ts = {0, 10000000}; // Too frequent. Use blocking_region

	int k;
	#ifdef BUILD_FOR_RUBY
	TRAP_BEG;
	#endif
	k = kevent (kqfd, NULL, 0, Karray, MaxEvents, &ts);
	#ifdef BUILD_FOR_RUBY
	TRAP_END;
	#endif

	struct kevent *ke = Karray;
	while (k > 0) {
		switch (ke->filter)
		{
			case EVFILT_VNODE:
				_HandleKqueueFileEvent (ke);
				break;

			case EVFILT_PROC:
				_HandleKqueuePidEvent (ke);
				break;

			case EVFILT_READ:
			case EVFILT_WRITE:
				EventableDescriptor *ed = (EventableDescriptor*) (ke->udata);
				assert (ed);

				if (ed->IsWatchOnly() && ed->GetSocket() == INVALID_SOCKET)
					break;

				if (ke->filter == EVFILT_READ)
					ed->Read();
				else if (ke->filter == EVFILT_WRITE)
					ed->Write();
				else
					cerr << "Discarding unknown kqueue event " << ke->filter << endl;

				break;
		}

		--k;
		++ke;
	}

	{ // cleanup dying sockets
		// vector::pop_back works in constant time.
		// TODO, rip this out and only delete the descriptors we know have died,
		// rather than traversing the whole list.
		// In kqueue, closing a descriptor automatically removes its event filters.

		int i, j;
		int nSockets = Descriptors.size();
		for (i=0, j=0; i < nSockets; i++) {
			EventableDescriptor *ed = Descriptors[i];
			assert (ed);
			if (ed->ShouldDelete()) {
				ModifiedDescriptors.erase (ed);
				delete ed;
			}
			else
				Descriptors [j++] = ed;
		}
		while ((size_t)j < Descriptors.size())
			Descriptors.pop_back();

	}

	{ // dispatch heartbeats
		if (gCurrentLoopTime >= NextHeartbeatTime) {
			NextHeartbeatTime = gCurrentLoopTime + HeartbeatInterval;

			for (unsigned int i=0; i < Descriptors.size(); i++) {
				EventableDescriptor *ed = Descriptors[i];
				assert (ed);
				ed->Heartbeat();
			}
		}
	}


	// TODO, replace this with rb_thread_blocking_region for 1.9 builds.
	#ifdef BUILD_FOR_RUBY
	if (!rb_thread_alone()) {
		rb_thread_schedule();
	}
	#endif

	return true;
	#else
	throw std::runtime_error ("kqueue is not implemented on this platform");
	#endif
}


/*********************************
EventMachine_t::_ModifyEpollEvent
*********************************/

void EventMachine_t::_ModifyEpollEvent (EventableDescriptor *ed)
{
	#ifdef HAVE_EPOLL
	if (bEpoll) {
		assert (epfd != -1);
		assert (ed);
		assert (ed->GetSocket() != INVALID_SOCKET);
		int e = epoll_ctl (epfd, EPOLL_CTL_MOD, ed->GetSocket(), ed->GetEpollEvent());
		if (e) {
			char buf [200];
			snprintf (buf, sizeof(buf)-1, "unable to modify epoll event: %s", strerror(errno));
			throw std::runtime_error (buf);
		}
	}
	#endif
}



/**************************
SelectData_t::SelectData_t
**************************/

SelectData_t::SelectData_t()
{
	maxsocket = 0;
	FD_ZERO (&fdreads);
	FD_ZERO (&fdwrites);
	FD_ZERO (&fderrors);
}


#ifdef BUILD_FOR_RUBY
/*****************
_SelectDataSelect
*****************/

#ifdef HAVE_TBR
static VALUE _SelectDataSelect (void *v)
{
	SelectData_t *sd = (SelectData_t*)v;
	sd->nSockets = select (sd->maxsocket+1, &(sd->fdreads), &(sd->fdwrites), &(sd->fderrors), &(sd->tv));
	return Qnil;
}
#endif

/*********************
SelectData_t::_Select
*********************/

int SelectData_t::_Select()
{
	#ifdef HAVE_TBR
	rb_thread_blocking_region (_SelectDataSelect, (void*)this, RUBY_UBF_IO, 0);
	return nSockets;
	#endif

	#ifndef HAVE_TBR
	return EmSelect (maxsocket+1, &fdreads, &fdwrites, &fderrors, &tv);
	#endif
}
#endif



/******************************
EventMachine_t::_RunSelectOnce
******************************/

bool EventMachine_t::_RunSelectOnce()
{
	// Crank the event machine once.
	// If there are no descriptors to process, then sleep
	// for a few hundred mills to avoid busy-looping.
	// Return T/F to indicate whether we should continue.
	// This is based on a select loop. Alternately provide epoll
	// if we know we're running on a 2.6 kernel.
	// epoll will be effective if we provide it as an alternative,
	// however it has the same problem interoperating with Ruby
	// threads that select does.

	//cerr << "X";

	/* This protection is now obsolete, because we will ALWAYS
	 * have at least one descriptor (the loop-breaker) to read.
	 */
	/*
	if (Descriptors.size() == 0) {
		#ifdef OS_UNIX
		timeval tv = {0, 200 * 1000};
		EmSelect (0, NULL, NULL, NULL, &tv);
		return true;
		#endif
		#ifdef OS_WIN32
		Sleep (200);
		return true;
		#endif
	}
	*/

	SelectData_t SelectData;
	/*
	fd_set fdreads, fdwrites;
	FD_ZERO (&fdreads);
	FD_ZERO (&fdwrites);

	int maxsocket = 0;
	*/

	// Always read the loop-breaker reader.
	// Changed 23Aug06, provisionally implemented for Windows with a UDP socket
	// running on localhost with a randomly-chosen port. (*Puke*)
	// Windows has a version of the Unix pipe() library function, but it doesn't
	// give you back descriptors that are selectable.
	FD_SET (LoopBreakerReader, &(SelectData.fdreads));
	if (SelectData.maxsocket < LoopBreakerReader)
		SelectData.maxsocket = LoopBreakerReader;

	// prepare the sockets for reading and writing
	size_t i;
	for (i = 0; i < Descriptors.size(); i++) {
		EventableDescriptor *ed = Descriptors[i];
		assert (ed);
		int sd = ed->GetSocket();
		if (ed->IsWatchOnly() && sd == INVALID_SOCKET)
			continue;
		assert (sd != INVALID_SOCKET);

		if (ed->SelectForRead())
			FD_SET (sd, &(SelectData.fdreads));
		if (ed->SelectForWrite())
			FD_SET (sd, &(SelectData.fdwrites));

		#ifdef OS_WIN32
		/* 21Sep09: on windows, a non-blocking connect() that fails does not come up as writable.
		   Instead, it is added to the error set. See http://www.mail-archive.com/openssl-users@openssl.org/msg58500.html
		*/
		FD_SET (sd, &(SelectData.fderrors));
		#endif

		if (SelectData.maxsocket < sd)
			SelectData.maxsocket = sd;
	}


	{ // read and write the sockets
		//timeval tv = {1, 0}; // Solaris fails if the microseconds member is >= 1000000.
		//timeval tv = Quantum;
		SelectData.tv = Quantum;
		int s = SelectData._Select();
		//rb_thread_blocking_region(xxx,(void*)&SelectData,RUBY_UBF_IO,0);
		//int s = EmSelect (SelectData.maxsocket+1, &(SelectData.fdreads), &(SelectData.fdwrites), NULL, &(SelectData.tv));
		//int s = SelectData.nSockets;
		if (s > 0) {
			/* Changed 01Jun07. We used to handle the Loop-breaker right here.
			 * Now we do it AFTER all the regular descriptors. There's an
			 * incredibly important and subtle reason for this. Code on
			 * loop breakers is sometimes used to cause the reactor core to
			 * cycle (for example, to allow outbound network buffers to drain).
			 * If a loop-breaker handler reschedules itself (say, after determining
			 * that the write buffers are still too full), then it will execute
			 * IMMEDIATELY if _ReadLoopBreaker is done here instead of after
			 * the other descriptors are processed. That defeats the whole purpose.
			 */
			for (i=0; i < Descriptors.size(); i++) {
				EventableDescriptor *ed = Descriptors[i];
				assert (ed);
				int sd = ed->GetSocket();
				if (ed->IsWatchOnly() && sd == INVALID_SOCKET)
					continue;
				assert (sd != INVALID_SOCKET);

				if (FD_ISSET (sd, &(SelectData.fdwrites)))
					ed->Write();
				if (FD_ISSET (sd, &(SelectData.fdreads)))
					ed->Read();
				if (FD_ISSET (sd, &(SelectData.fderrors)))
					ed->HandleError();
			}

			if (FD_ISSET (LoopBreakerReader, &(SelectData.fdreads)))
				_ReadLoopBreaker();
		}
		else if (s < 0) {
			// select can fail on error in a handful of ways.
			// If this happens, then wait for a little while to avoid busy-looping.
			// If the error was EINTR, we probably caught SIGCHLD or something,
			// so keep the wait short.
			timeval tv = {0, ((errno == EINTR) ? 5 : 50) * 1000};
			EmSelect (0, NULL, NULL, NULL, &tv);
		}
	}


	{ // dispatch heartbeats
		if (gCurrentLoopTime >= NextHeartbeatTime) {
			NextHeartbeatTime = gCurrentLoopTime + HeartbeatInterval;

			for (i=0; i < Descriptors.size(); i++) {
				EventableDescriptor *ed = Descriptors[i];
				assert (ed);
				ed->Heartbeat();
			}
		}
	}

	{ // cleanup dying sockets
		// vector::pop_back works in constant time.
		int i, j;
		int nSockets = Descriptors.size();
		for (i=0, j=0; i < nSockets; i++) {
			EventableDescriptor *ed = Descriptors[i];
			assert (ed);
			if (ed->ShouldDelete())
				delete ed;
			else
				Descriptors [j++] = ed;
		}
		while ((size_t)j < Descriptors.size())
			Descriptors.pop_back();

	}

	return true;
}


/********************************
EventMachine_t::_ReadLoopBreaker
********************************/

void EventMachine_t::_ReadLoopBreaker()
{
	/* The loop breaker has selected readable.
	 * Read it ONCE (it may block if we try to read it twice)
	 * and send a loop-break event back to user code.
	 */
	char buffer [1024];
	read (LoopBreakerReader, buffer, sizeof(buffer));
	if (EventCallback)
		(*EventCallback)(NULL, EM_LOOPBREAK_SIGNAL, "", 0);
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
		multimap<Int64,Timer_t>::iterator i = Timers.begin();
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

const unsigned long EventMachine_t::InstallOneshotTimer (int milliseconds)
{
	if (Timers.size() > MaxOutstandingTimers)
		return false;
	// Don't use the global loop-time variable here, because we might
	// get called before the main event machine is running.

	#ifdef OS_UNIX
	struct timeval tv;
	gettimeofday (&tv, NULL);
	Int64 fire_at = (((Int64)(tv.tv_sec)) * 1000000LL) + ((Int64)(tv.tv_usec));
	fire_at += ((Int64)milliseconds) * 1000LL;
	#endif

	#ifdef OS_WIN32
	unsigned tick = GetTickCount();
	if (tick < gLastTickCount)
		gTickCountTickover += 1;
	gLastTickCount = tick;

	Int64 fire_at = ((Int64)gTickCountTickover << 32) + (Int64)tick;
	fire_at += (Int64)milliseconds;
	#endif

	Timer_t t;
	#ifndef HAVE_MAKE_PAIR
	multimap<Int64,Timer_t>::iterator i = Timers.insert (multimap<Int64,Timer_t>::value_type (fire_at, t));
	#else
	multimap<Int64,Timer_t>::iterator i = Timers.insert (make_pair (fire_at, t));
	#endif
	return i->second.GetBinding();
}


/*******************************
EventMachine_t::ConnectToServer
*******************************/

const unsigned long EventMachine_t::ConnectToServer (const char *bind_addr, int bind_port, const char *server, int port)
{
	/* We want to spend no more than a few seconds waiting for a connection
	 * to a remote host. So we use a nonblocking connect.
	 * Linux disobeys the usual rules for nonblocking connects.
	 * Per Stevens (UNP p.410), you expect a nonblocking connect to select
	 * both readable and writable on error, and not to return EINPROGRESS
	 * if the connect can be fulfilled immediately. Linux violates both
	 * of these expectations.
	 * Any kind of nonblocking connect on Linux returns EINPROGRESS.
	 * The socket will then return writable when the disposition of the
	 * connect is known, but it will not also be readable in case of
	 * error! Weirdly, it will be readable in case there is data to read!!!
	 * (Which can happen with protocols like SSH and SMTP.)
	 * I suppose if you were so inclined you could consider this logical,
	 * but it's not the way Unix has historically done it.
	 * So we ignore the readable flag and read getsockopt to see if there
	 * was an error connecting. A select timeout works as expected.
	 * In regard to getsockopt: Linux does the Berkeley-style thing,
	 * not the Solaris-style, and returns zero with the error code in
	 * the error parameter.
	 * Return the binding-text of the newly-created pending connection,
	 * or NULL if there was a problem.
	 */

	if (!server || !*server || !port)
		throw std::runtime_error ("invalid server or port");

	int family, bind_size;
	struct sockaddr bind_as, *bind_as_ptr = name2address (server, port, &family, &bind_size);
	if (!bind_as_ptr)
		throw std::runtime_error ("unable to resolve server address");
	bind_as = *bind_as_ptr; // copy because name2address points to a static

	int sd = socket (family, SOCK_STREAM, 0);
	if (sd == INVALID_SOCKET)
		throw std::runtime_error ("unable to create new socket");

	/*
	sockaddr_in pin;
	unsigned long HostAddr;

	HostAddr = inet_addr (server);
	if (HostAddr == INADDR_NONE) {
		hostent *hp = gethostbyname ((char*)server); // Windows requires (char*)
		if (!hp) {
			// TODO: This gives the caller a fatal error. Not good.
			// They can respond by catching RuntimeError (blecch).
			// Possibly we need to fire an unbind event and provide
			// a status code so user code can detect the cause of the
			// failure.
			return NULL;
		}
		HostAddr = ((in_addr*)(hp->h_addr))->s_addr;
	}

	memset (&pin, 0, sizeof(pin));
	pin.sin_family = AF_INET;
	pin.sin_addr.s_addr = HostAddr;
	pin.sin_port = htons (port);

	int sd = socket (AF_INET, SOCK_STREAM, 0);
	if (sd == INVALID_SOCKET)
		return NULL;
	*/

	// From here on, ALL error returns must close the socket.
	// Set the new socket nonblocking.
	if (!SetSocketNonblocking (sd)) {
		closesocket (sd);
		throw std::runtime_error ("unable to set socket as non-blocking");
	}
	// Disable slow-start (Nagle algorithm).
	int one = 1;
	setsockopt (sd, IPPROTO_TCP, TCP_NODELAY, (char*) &one, sizeof(one));
	// Set reuseaddr to improve performance on restarts
	setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, (char*) &one, sizeof(one));

	if (bind_addr) {
		int bind_to_size, bind_to_family;
		struct sockaddr *bind_to = name2address (bind_addr, bind_port, &bind_to_family, &bind_to_size);
		if (!bind_to) {
			closesocket (sd);
			throw std::runtime_error ("invalid bind address");
		}
		if (bind (sd, bind_to, bind_to_size) < 0) {
			closesocket (sd);
			throw std::runtime_error ("couldn't bind to address");
		}
	}

	unsigned long out = NULL;

	#ifdef OS_UNIX
	//if (connect (sd, (sockaddr*)&pin, sizeof pin) == 0) {
	if (connect (sd, &bind_as, bind_size) == 0) {
		// This is a connect success, which Linux appears
		// never to give when the socket is nonblocking,
		// even if the connection is intramachine or to
		// localhost.

		/* Changed this branch 08Aug06. Evidently some kernels
		 * (FreeBSD for example) will actually return success from
		 * a nonblocking connect. This is a pretty simple case,
		 * just set up the new connection and clear the pending flag.
		 * Thanks to Chris Ochs for helping track this down.
		 * This branch never gets taken on Linux or (oddly) OSX.
		 * The original behavior was to throw an unimplemented,
		 * which the user saw as a fatal exception. Very unfriendly.
		 *
		 * Tweaked 10Aug06. Even though the connect disposition is
		 * known, we still set the connect-pending flag. That way
		 * some needed initialization will happen in the ConnectionDescriptor.
		 * (To wit, the ConnectionCompleted event gets sent to the client.)
		 */
		ConnectionDescriptor *cd = new ConnectionDescriptor (sd, this);
		if (!cd)
			throw std::runtime_error ("no connection allocated");
		cd->SetConnectPending (true);
		Add (cd);
		out = cd->GetBinding();
	}
	else if (errno == EINPROGRESS) {
		// Errno will generally always be EINPROGRESS, but on Linux
		// we have to look at getsockopt to be sure what really happened.
		int error;
		socklen_t len;
		len = sizeof(error);
		int o = getsockopt (sd, SOL_SOCKET, SO_ERROR, &error, &len);
		if ((o == 0) && (error == 0)) {
			// Here, there's no disposition.
			// Put the connection on the stack and wait for it to complete
			// or time out.
			ConnectionDescriptor *cd = new ConnectionDescriptor (sd, this);
			if (!cd)
				throw std::runtime_error ("no connection allocated");
			cd->SetConnectPending (true);
			Add (cd);
			out = cd->GetBinding();
		}
		else {
			/* This could be connection refused or some such thing.
			 * We will come here on Linux if a localhost connection fails.
			 * Changed 16Jul06: Originally this branch was a no-op, and
			 * we'd drop down to the end of the method, close the socket,
			 * and return NULL, which would cause the caller to GET A
			 * FATAL EXCEPTION. Now we keep the socket around but schedule an
			 * immediate close on it, so the caller will get a close-event
			 * scheduled on it. This was only an issue for localhost connections
			 * to non-listening ports. We may eventually need to revise this
			 * revised behavior, in case it causes problems like making it hard
			 * for people to know that a failure occurred.
			 */
			ConnectionDescriptor *cd = new ConnectionDescriptor (sd, this);
			if (!cd)
				throw std::runtime_error ("no connection allocated");
			cd->ScheduleClose (false);
			Add (cd);
			out = cd->GetBinding();
		}
	}
	else {
		// The error from connect was something other then EINPROGRESS.
	}
	#endif

	#ifdef OS_WIN32
	//if (connect (sd, (sockaddr*)&pin, sizeof pin) == 0) {
	if (connect (sd, &bind_as, bind_size) == 0) {
		// This is a connect success, which Windows appears
		// never to give when the socket is nonblocking,
		// even if the connection is intramachine or to
		// localhost.
		throw std::runtime_error ("unimplemented");
	}
	else if (WSAGetLastError() == WSAEWOULDBLOCK) {
		// Here, there's no disposition.
		// Windows appears not to surface refused connections or
		// such stuff at this point.
		// Put the connection on the stack and wait for it to complete
		// or time out.
		ConnectionDescriptor *cd = new ConnectionDescriptor (sd, this);
		if (!cd)
			throw std::runtime_error ("no connection allocated");
		cd->SetConnectPending (true);
		Add (cd);
		out = cd->GetBinding();
	}
	else {
		// The error from connect was something other then WSAEWOULDBLOCK.
	}

	#endif

	if (!out)
		closesocket (sd);
	return out;
}

/***********************************
EventMachine_t::ConnectToUnixServer
***********************************/

const unsigned long EventMachine_t::ConnectToUnixServer (const char *server)
{
	/* Connect to a Unix-domain server, which by definition is running
	 * on the same host.
	 * There is no meaningful implementation on Windows.
	 * There's no need to do a nonblocking connect, since the connection
	 * is always local and can always be fulfilled immediately.
	 */

	#ifdef OS_WIN32
	throw std::runtime_error ("unix-domain connection unavailable on this platform");
	return NULL;
	#endif

	// The whole rest of this function is only compiled on Unix systems.
	#ifdef OS_UNIX

	unsigned long out = NULL;

	if (!server || !*server)
		return NULL;

	sockaddr_un pun;
	memset (&pun, 0, sizeof(pun));
	pun.sun_family = AF_LOCAL;

	// You ordinarily expect the server name field to be at least 1024 bytes long,
	// but on Linux it can be MUCH shorter.
	if (strlen(server) >= sizeof(pun.sun_path))
		throw std::runtime_error ("unix-domain server name is too long");


	strcpy (pun.sun_path, server);

	int fd = socket (AF_LOCAL, SOCK_STREAM, 0);
	if (fd == INVALID_SOCKET)
		return NULL;

	// From here on, ALL error returns must close the socket.
	// NOTE: At this point, the socket is still a blocking socket.
	if (connect (fd, (struct sockaddr*)&pun, sizeof(pun)) != 0) {
		closesocket (fd);
		return NULL;
	}

	// Set the newly-connected socket nonblocking.
	if (!SetSocketNonblocking (fd)) {
		closesocket (fd);
		return NULL;
	}

	// Set up a connection descriptor and add it to the event-machine.
	// Observe, even though we know the connection status is connect-success,
	// we still set the "pending" flag, so some needed initializations take
	// place.
	ConnectionDescriptor *cd = new ConnectionDescriptor (fd, this);
	if (!cd)
		throw std::runtime_error ("no connection allocated");
	cd->SetConnectPending (true);
	Add (cd);
	out = cd->GetBinding();

	if (!out)
		closesocket (fd);

	return out;
	#endif
}

/************************
EventMachine_t::AttachFD
************************/

const unsigned long EventMachine_t::AttachFD (int fd, bool watch_mode)
{
	#ifdef OS_UNIX
	if (fcntl(fd, F_GETFL, 0) < 0)
		throw std::runtime_error ("invalid file descriptor");
	#endif

	#ifdef OS_WIN32
	// TODO: add better check for invalid file descriptors (see ioctlsocket or getsockopt)
	if (fd == INVALID_SOCKET)
		throw std::runtime_error ("invalid file descriptor");
	#endif

	{// Check for duplicate descriptors
		size_t i;
		for (i = 0; i < Descriptors.size(); i++) {
			EventableDescriptor *ed = Descriptors[i];
			assert (ed);
			if (ed->GetSocket() == fd)
				throw std::runtime_error ("adding existing descriptor");
		}

		for (i = 0; i < NewDescriptors.size(); i++) {
			EventableDescriptor *ed = NewDescriptors[i];
			assert (ed);
			if (ed->GetSocket() == fd)
				throw std::runtime_error ("adding existing new descriptor");
		}
	}

	if (!watch_mode)
		SetSocketNonblocking(fd);

	ConnectionDescriptor *cd = new ConnectionDescriptor (fd, this);
	if (!cd)
		throw std::runtime_error ("no connection allocated");

	cd->SetWatchOnly(watch_mode);
	cd->SetConnectPending (false);

	Add (cd);

	const unsigned long out = cd->GetBinding();
	return out;
}

/************************
EventMachine_t::DetachFD
************************/

int EventMachine_t::DetachFD (EventableDescriptor *ed)
{
	if (!ed)
		throw std::runtime_error ("detaching bad descriptor");

	int fd = ed->GetSocket();

	#ifdef HAVE_EPOLL
	if (bEpoll) {
		if (ed->GetSocket() != INVALID_SOCKET) {
			assert (epfd != -1);
			int e = epoll_ctl (epfd, EPOLL_CTL_DEL, ed->GetSocket(), ed->GetEpollEvent());
			// ENOENT or EBADF are not errors because the socket may be already closed when we get here.
			if (e && (errno != ENOENT) && (errno != EBADF)) {
				char buf [200];
				snprintf (buf, sizeof(buf)-1, "unable to delete epoll event: %s", strerror(errno));
				throw std::runtime_error (buf);
			}
		}
	}
	#endif

	#ifdef HAVE_KQUEUE
	if (bKqueue) {
		// remove any read/write events for this fd
		struct kevent k;
		EV_SET (&k, ed->GetSocket(), EVFILT_READ | EVFILT_WRITE, EV_DELETE, 0, 0, ed);
		int t = kevent (kqfd, &k, 1, NULL, 0, NULL);
		if (t < 0 && (errno != ENOENT) && (errno != EBADF)) {
			char buf [200];
			snprintf (buf, sizeof(buf)-1, "unable to delete kqueue event: %s", strerror(errno));
			throw std::runtime_error (buf);
		}
	}
	#endif

	// Prevent the descriptor from being modified, in case DetachFD was called from a timer or next_tick
	ModifiedDescriptors.erase (ed);

	// Set MySocket = INVALID_SOCKET so ShouldDelete() is true (and the descriptor gets deleted and removed),
	// and also to prevent anyone from calling close() on the detached fd
	ed->SetSocketInvalid();

	return fd;
}

/************
name2address
************/

struct sockaddr *name2address (const char *server, int port, int *family, int *bind_size)
{
	// THIS IS NOT RE-ENTRANT OR THREADSAFE. Optimize for speed.
	// Check the more-common cases first.
	// Return NULL if no resolution.

	static struct sockaddr_in in4;
	#ifndef __CYGWIN__
	static struct sockaddr_in6 in6;
	#endif
	struct hostent *hp;

	if (!server || !*server)
		server = "0.0.0.0";

	memset (&in4, 0, sizeof(in4));
	if ( (in4.sin_addr.s_addr = inet_addr (server)) != INADDR_NONE) {
		if (family)
			*family = AF_INET;
		if (bind_size)
			*bind_size = sizeof(in4);
		in4.sin_family = AF_INET;
		in4.sin_port = htons (port);
		return (struct sockaddr*)&in4;
	}

	#if defined(OS_UNIX) && !defined(__CYGWIN__)
	memset (&in6, 0, sizeof(in6));
	if (inet_pton (AF_INET6, server, in6.sin6_addr.s6_addr) > 0) {
		if (family)
			*family = AF_INET6;
		if (bind_size)
			*bind_size = sizeof(in6);
		in6.sin6_family = AF_INET6;
		in6.sin6_port = htons (port);
		return (struct sockaddr*)&in6;
	}
	#endif

	#ifdef OS_WIN32
	// TODO, must complete this branch. Windows doesn't have inet_pton.
	// A possible approach is to make a getaddrinfo call with the supplied
	// server address, constraining the hints to ipv6 and seeing if we
	// get any addresses.
	// For the time being, Ipv6 addresses aren't supported on Windows.
	#endif

	hp = gethostbyname ((char*)server); // Windows requires the cast.
	if (hp) {
		in4.sin_addr.s_addr = ((in_addr*)(hp->h_addr))->s_addr;
		if (family)
			*family = AF_INET;
		if (bind_size)
			*bind_size = sizeof(in4);
		in4.sin_family = AF_INET;
		in4.sin_port = htons (port);
		return (struct sockaddr*)&in4;
	}

	return NULL;
}


/*******************************
EventMachine_t::CreateTcpServer
*******************************/

const unsigned long EventMachine_t::CreateTcpServer (const char *server, int port)
{
	/* Create a TCP-acceptor (server) socket and add it to the event machine.
	 * Return the binding of the new acceptor to the caller.
	 * This binding will be referenced when the new acceptor sends events
	 * to indicate accepted connections.
	 */


	int family, bind_size;
	struct sockaddr *bind_here = name2address (server, port, &family, &bind_size);
	if (!bind_here)
		return NULL;

	unsigned long output_binding = NULL;

	//struct sockaddr_in sin;

	int sd_accept = socket (family, SOCK_STREAM, 0);
	if (sd_accept == INVALID_SOCKET) {
		goto fail;
	}

	/*
	memset (&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons (port);

	if (server && *server) {
		sin.sin_addr.s_addr = inet_addr (server);
		if (sin.sin_addr.s_addr == INADDR_NONE) {
			hostent *hp = gethostbyname ((char*)server); // Windows requires the cast.
			if (hp == NULL) {
				//__warning ("hostname not resolved: ", server);
				goto fail;
			}
			sin.sin_addr.s_addr = ((in_addr*)(hp->h_addr))->s_addr;
		}
	}
	*/

	{ // set reuseaddr to improve performance on restarts.
		int oval = 1;
		if (setsockopt (sd_accept, SOL_SOCKET, SO_REUSEADDR, (char*)&oval, sizeof(oval)) < 0) {
			//__warning ("setsockopt failed while creating listener","");
			goto fail;
		}
	}

	{ // set CLOEXEC. Only makes sense on Unix
		#ifdef OS_UNIX
		int cloexec = fcntl (sd_accept, F_GETFD, 0);
		assert (cloexec >= 0);
		cloexec |= FD_CLOEXEC;
		fcntl (sd_accept, F_SETFD, cloexec);
		#endif
	}


	//if (bind (sd_accept, (struct sockaddr*)&sin, sizeof(sin))) {
	if (bind (sd_accept, bind_here, bind_size)) {
		//__warning ("binding failed");
		goto fail;
	}

	if (listen (sd_accept, 100)) {
		//__warning ("listen failed");
		goto fail;
	}

	{
		// Set the acceptor non-blocking.
		// THIS IS CRUCIALLY IMPORTANT because we read it in a select loop.
		if (!SetSocketNonblocking (sd_accept)) {
		//int val = fcntl (sd_accept, F_GETFL, 0);
		//if (fcntl (sd_accept, F_SETFL, val | O_NONBLOCK) == -1) {
			goto fail;
		}
	}

	{ // Looking good.
		AcceptorDescriptor *ad = new AcceptorDescriptor (sd_accept, this);
		if (!ad)
			throw std::runtime_error ("unable to allocate acceptor");
		Add (ad);
		output_binding = ad->GetBinding();
	}

	return output_binding;

	fail:
	if (sd_accept != INVALID_SOCKET)
		closesocket (sd_accept);
	return NULL;
}


/**********************************
EventMachine_t::OpenDatagramSocket
**********************************/

const unsigned long EventMachine_t::OpenDatagramSocket (const char *address, int port)
{
	unsigned long output_binding = NULL;

	int sd = socket (AF_INET, SOCK_DGRAM, 0);
	if (sd == INVALID_SOCKET)
		goto fail;
	// from here on, early returns must close the socket!


	struct sockaddr_in sin;
	memset (&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons (port);


	if (address && *address) {
		sin.sin_addr.s_addr = inet_addr (address);
		if (sin.sin_addr.s_addr == INADDR_NONE) {
			hostent *hp = gethostbyname ((char*)address); // Windows requires the cast.
			if (hp == NULL)
				goto fail;
			sin.sin_addr.s_addr = ((in_addr*)(hp->h_addr))->s_addr;
		}
	}
	else
		sin.sin_addr.s_addr = htonl (INADDR_ANY);


	// Set the new socket nonblocking.
	{
		if (!SetSocketNonblocking (sd))
		//int val = fcntl (sd, F_GETFL, 0);
		//if (fcntl (sd, F_SETFL, val | O_NONBLOCK) == -1)
			goto fail;
	}

	if (bind (sd, (struct sockaddr*)&sin, sizeof(sin)) != 0)
		goto fail;

	{ // Looking good.
		DatagramDescriptor *ds = new DatagramDescriptor (sd, this);
		if (!ds)
			throw std::runtime_error ("unable to allocate datagram-socket");
		Add (ds);
		output_binding = ds->GetBinding();
	}

	return output_binding;

	fail:
	if (sd != INVALID_SOCKET)
		closesocket (sd);
	return NULL;
}



/*******************
EventMachine_t::Add
*******************/

void EventMachine_t::Add (EventableDescriptor *ed)
{
	if (!ed)
		throw std::runtime_error ("added bad descriptor");
	ed->SetEventCallback (EventCallback);
	NewDescriptors.push_back (ed);
}


/*******************************
EventMachine_t::ArmKqueueWriter
*******************************/

void EventMachine_t::ArmKqueueWriter (EventableDescriptor *ed)
{
	#ifdef HAVE_KQUEUE
	if (bKqueue) {
		if (!ed)
			throw std::runtime_error ("added bad descriptor");
		struct kevent k;
		EV_SET (&k, ed->GetSocket(), EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, ed);
		int t = kevent (kqfd, &k, 1, NULL, 0, NULL);
		if (t < 0) {
			char buf [200];
			snprintf (buf, sizeof(buf)-1, "arm kqueue writer failed on %d: %s", ed->GetSocket(), strerror(errno));
			throw std::runtime_error (buf);
		}
	}
	#endif
}

/*******************************
EventMachine_t::ArmKqueueReader
*******************************/

void EventMachine_t::ArmKqueueReader (EventableDescriptor *ed)
{
	#ifdef HAVE_KQUEUE
	if (bKqueue) {
		if (!ed)
			throw std::runtime_error ("added bad descriptor");
		struct kevent k;
		EV_SET (&k, ed->GetSocket(), EVFILT_READ, EV_ADD, 0, 0, ed);
		int t = kevent (kqfd, &k, 1, NULL, 0, NULL);
		if (t < 0) {
			char buf [200];
			snprintf (buf, sizeof(buf)-1, "arm kqueue reader failed on %d: %s", ed->GetSocket(), strerror(errno));
			throw std::runtime_error (buf);
		}
	}
	#endif
}

/**********************************
EventMachine_t::_AddNewDescriptors
**********************************/

void EventMachine_t::_AddNewDescriptors()
{
	/* Avoid adding descriptors to the main descriptor list
	 * while we're actually traversing the list.
	 * Any descriptors that are added as a result of processing timers
	 * or acceptors should go on a temporary queue and then added
	 * while we're not traversing the main list.
	 * Also, it (rarely) happens that a newly-created descriptor
	 * is immediately scheduled to close. It might be a good
	 * idea not to bother scheduling these for I/O but if
	 * we do that, we might bypass some important processing.
	 */

	for (size_t i = 0; i < NewDescriptors.size(); i++) {
		EventableDescriptor *ed = NewDescriptors[i];
		if (ed == NULL)
			throw std::runtime_error ("adding bad descriptor");

		#if HAVE_EPOLL
		if (bEpoll) {
			assert (epfd != -1);
			int e = epoll_ctl (epfd, EPOLL_CTL_ADD, ed->GetSocket(), ed->GetEpollEvent());
			if (e) {
				char buf [200];
				snprintf (buf, sizeof(buf)-1, "unable to add new descriptor: %s", strerror(errno));
				throw std::runtime_error (buf);
			}
		}
		#endif

		#if HAVE_KQUEUE
		/*
		if (bKqueue) {
			// INCOMPLETE. Some descriptors don't want to be readable.
			assert (kqfd != -1);
			struct kevent k;
			EV_SET (&k, ed->GetSocket(), EVFILT_READ, EV_ADD, 0, 0, ed);
			int t = kevent (kqfd, &k, 1, NULL, 0, NULL);
			assert (t == 0);
		}
		*/
		#endif

		Descriptors.push_back (ed);
	}
	NewDescriptors.clear();
}


/**********************************
EventMachine_t::_ModifyDescriptors
**********************************/

void EventMachine_t::_ModifyDescriptors()
{
	/* For implementations which don't level check every descriptor on
	 * every pass through the machine, as select does.
	 * If we're not selecting, then descriptors need a way to signal to the
	 * machine that their readable or writable status has changed.
	 * That's what the ::Modify call is for. We do it this way to avoid
	 * modifying descriptors during the loop traversal, where it can easily
	 * happen that an object (like a UDP socket) gets data written on it by
	 * the application during #post_init. That would take place BEFORE the
	 * descriptor even gets added to the epoll descriptor, so the modify
	 * operation will crash messily.
	 * Another really messy possibility is for a descriptor to put itself
	 * on the Modified list, and then get deleted before we get here.
	 * Remember, deletes happen after the I/O traversal and before the
	 * next pass through here. So we have to make sure when we delete a
	 * descriptor to remove it from the Modified list.
	 */

	#ifdef HAVE_EPOLL
	if (bEpoll) {
		set<EventableDescriptor*>::iterator i = ModifiedDescriptors.begin();
		while (i != ModifiedDescriptors.end()) {
			assert (*i);
			_ModifyEpollEvent (*i);
			++i;
		}
	}
	#endif

	ModifiedDescriptors.clear();
}


/**********************
EventMachine_t::Modify
**********************/

void EventMachine_t::Modify (EventableDescriptor *ed)
{
	if (!ed)
		throw std::runtime_error ("modified bad descriptor");
	ModifiedDescriptors.insert (ed);
}


/***********************************
EventMachine_t::_OpenFileForWriting
***********************************/

const unsigned long EventMachine_t::_OpenFileForWriting (const char *filename)
{
  /*
	 * Return the binding-text of the newly-opened file,
	 * or NULL if there was a problem.
	 */

	if (!filename || !*filename)
		return NULL;

  int fd = open (filename, O_CREAT|O_TRUNC|O_WRONLY|O_NONBLOCK, 0644);
  
	FileStreamDescriptor *fsd = new FileStreamDescriptor (fd, this);
  if (!fsd)
  	throw std::runtime_error ("no file-stream allocated");
  Add (fsd);
  return fsd->GetBinding();

}


/**************************************
EventMachine_t::CreateUnixDomainServer
**************************************/

const unsigned long EventMachine_t::CreateUnixDomainServer (const char *filename)
{
	/* Create a UNIX-domain acceptor (server) socket and add it to the event machine.
	 * Return the binding of the new acceptor to the caller.
	 * This binding will be referenced when the new acceptor sends events
	 * to indicate accepted connections.
	 * THERE IS NO MEANINGFUL IMPLEMENTATION ON WINDOWS.
	 */

	#ifdef OS_WIN32
	throw std::runtime_error ("unix-domain server unavailable on this platform");
	#endif

	// The whole rest of this function is only compiled on Unix systems.
	#ifdef OS_UNIX
	unsigned long output_binding = NULL;

	struct sockaddr_un s_sun;

	int sd_accept = socket (AF_LOCAL, SOCK_STREAM, 0);
	if (sd_accept == INVALID_SOCKET) {
		goto fail;
	}

	if (!filename || !*filename)
		goto fail;
	unlink (filename);

	bzero (&s_sun, sizeof(s_sun));
	s_sun.sun_family = AF_LOCAL;
	strncpy (s_sun.sun_path, filename, sizeof(s_sun.sun_path)-1);

	// don't bother with reuseaddr for a local socket.

	{ // set CLOEXEC. Only makes sense on Unix
		#ifdef OS_UNIX
		int cloexec = fcntl (sd_accept, F_GETFD, 0);
		assert (cloexec >= 0);
		cloexec |= FD_CLOEXEC;
		fcntl (sd_accept, F_SETFD, cloexec);
		#endif
	}

	if (bind (sd_accept, (struct sockaddr*)&s_sun, sizeof(s_sun))) {
		//__warning ("binding failed");
		goto fail;
	}

	if (listen (sd_accept, 100)) {
		//__warning ("listen failed");
		goto fail;
	}

	{
		// Set the acceptor non-blocking.
		// THIS IS CRUCIALLY IMPORTANT because we read it in a select loop.
		if (!SetSocketNonblocking (sd_accept)) {
		//int val = fcntl (sd_accept, F_GETFL, 0);
		//if (fcntl (sd_accept, F_SETFL, val | O_NONBLOCK) == -1) {
			goto fail;
		}
	}

	{ // Looking good.
		AcceptorDescriptor *ad = new AcceptorDescriptor (sd_accept, this);
		if (!ad)
			throw std::runtime_error ("unable to allocate acceptor");
		Add (ad);
		output_binding = ad->GetBinding();
	}

	return output_binding;

	fail:
	if (sd_accept != INVALID_SOCKET)
		closesocket (sd_accept);
	return NULL;
	#endif // OS_UNIX
}


/*********************
EventMachine_t::Popen
*********************/
#if OBSOLETE
const char *EventMachine_t::Popen (const char *cmd, const char *mode)
{
	#ifdef OS_WIN32
	throw std::runtime_error ("popen is currently unavailable on this platform");
	#endif

	// The whole rest of this function is only compiled on Unix systems.
	// Eventually we need this functionality (or a full-duplex equivalent) on Windows.
	#ifdef OS_UNIX
	const char *output_binding = NULL;

	FILE *fp = popen (cmd, mode);
	if (!fp)
		return NULL;

	// From here, all early returns must pclose the stream.

	// According to the pipe(2) manpage, descriptors returned from pipe have both
	// CLOEXEC and NONBLOCK clear. Do NOT set CLOEXEC. DO set nonblocking.
	if (!SetSocketNonblocking (fileno (fp))) {
		pclose (fp);
		return NULL;
	}

	{ // Looking good.
		PipeDescriptor *pd = new PipeDescriptor (fp, this);
		if (!pd)
			throw std::runtime_error ("unable to allocate pipe");
		Add (pd);
		output_binding = pd->GetBinding();
	}

	return output_binding;
	#endif
}
#endif // OBSOLETE

/**************************
EventMachine_t::Socketpair
**************************/

const unsigned long EventMachine_t::Socketpair (char * const*cmd_strings)
{
	#ifdef OS_WIN32
	throw std::runtime_error ("socketpair is currently unavailable on this platform");
	#endif

	// The whole rest of this function is only compiled on Unix systems.
	// Eventually we need this functionality (or a full-duplex equivalent) on Windows.
	#ifdef OS_UNIX
	// Make sure the incoming array of command strings is sane.
	if (!cmd_strings)
		return NULL;
	int j;
	for (j=0; j < 100 && cmd_strings[j]; j++)
		;
	if ((j==0) || (j==100))
		return NULL;

	unsigned long output_binding = NULL;

	int sv[2];
	if (socketpair (AF_LOCAL, SOCK_STREAM, 0, sv) < 0)
		return NULL;
	// from here, all early returns must close the pair of sockets.

	// Set the parent side of the socketpair nonblocking.
	// We don't care about the child side, and most child processes will expect their
	// stdout to be blocking. Thanks to Duane Johnson and Bill Kelly for pointing this out.
	// Obviously DON'T set CLOEXEC.
	if (!SetSocketNonblocking (sv[0])) {
		close (sv[0]);
		close (sv[1]);
		return NULL;
	}

	pid_t f = fork();
	if (f > 0) {
		close (sv[1]);
		PipeDescriptor *pd = new PipeDescriptor (sv[0], f, this);
		if (!pd)
			throw std::runtime_error ("unable to allocate pipe");
		Add (pd);
		output_binding = pd->GetBinding();
	}
	else if (f == 0) {
		close (sv[0]);
		dup2 (sv[1], STDIN_FILENO);
		close (sv[1]);
		dup2 (STDIN_FILENO, STDOUT_FILENO);
		execvp (cmd_strings[0], cmd_strings+1);
		exit (-1); // end the child process if the exec doesn't work.
	}
	else
		throw std::runtime_error ("no fork");

	return output_binding;
	#endif
}


/****************************
EventMachine_t::OpenKeyboard
****************************/

const unsigned long EventMachine_t::OpenKeyboard()
{
	KeyboardDescriptor *kd = new KeyboardDescriptor (this);
	if (!kd)
		throw std::runtime_error ("no keyboard-object allocated");
	Add (kd);
	return kd->GetBinding();
}


/**********************************
EventMachine_t::GetConnectionCount
**********************************/

int EventMachine_t::GetConnectionCount ()
{
	return Descriptors.size() + NewDescriptors.size();
}


/************************
EventMachine_t::WatchPid
************************/

const unsigned long EventMachine_t::WatchPid (int pid)
{
	#ifdef HAVE_KQUEUE
	if (!bKqueue)
		throw std::runtime_error("must enable kqueue");

	struct kevent event;
	int kqres;

	EV_SET(&event, pid, EVFILT_PROC, EV_ADD, NOTE_EXIT | NOTE_FORK, 0, 0);

	// Attempt to register the event
	kqres = kevent(kqfd, &event, 1, NULL, 0, NULL);
	if (kqres == -1) {
		char errbuf[200];
		sprintf(errbuf, "failed to register file watch descriptor with kqueue: %s", strerror(errno));
		throw std::runtime_error(errbuf);
	}
	#endif

	#ifdef HAVE_KQUEUE
	Bindable_t* b = new Bindable_t();
	Pids.insert(make_pair (pid, b));

	return b->GetBinding();
	#endif

	throw std::runtime_error("no pid watching support on this system");
}

/**************************
EventMachine_t::UnwatchPid
**************************/

void EventMachine_t::UnwatchPid (int pid)
{
	Bindable_t *b = Pids[pid];
	assert(b);
	Pids.erase(pid);

	#ifdef HAVE_KQUEUE
	struct kevent k;

	EV_SET(&k, pid, EVFILT_PROC, EV_DELETE, 0, 0, 0);
	/*int t =*/ kevent (kqfd, &k, 1, NULL, 0, NULL);
	// t==-1 if the process already exited; ignore this for now
	#endif

	if (EventCallback)
		(*EventCallback)(b->GetBinding(), EM_CONNECTION_UNBOUND, NULL, 0);

	delete b;
}

void EventMachine_t::UnwatchPid (const unsigned long sig)
{
	for(map<int, Bindable_t*>::iterator i=Pids.begin(); i != Pids.end(); i++)
	{
		if (i->second->GetBinding() == sig) {
			UnwatchPid (i->first);
			return;
		}
	}

	throw std::runtime_error("attempted to remove invalid pid signature");
}


/*************************
EventMachine_t::WatchFile
*************************/

const unsigned long EventMachine_t::WatchFile (const char *fpath)
{
	struct stat sb;
	int sres;
	int wd = -1;

	sres = stat(fpath, &sb);

	if (sres == -1) {
		char errbuf[300];
		sprintf(errbuf, "error registering file %s for watching: %s", fpath, strerror(errno));
		throw std::runtime_error(errbuf);
	}

	#ifdef HAVE_INOTIFY
	if (!inotify) {
		inotify = new InotifyDescriptor(this);
		assert (inotify);
		Add(inotify);
	}

	wd = inotify_add_watch(inotify->GetSocket(), fpath, IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF);
	if (wd == -1) {
		char errbuf[300];
		sprintf(errbuf, "failed to open file %s for registering with inotify: %s", fpath, strerror(errno));
		throw std::runtime_error(errbuf);
	}
	#endif

	#ifdef HAVE_KQUEUE
	if (!bKqueue)
		throw std::runtime_error("must enable kqueue");

	// With kqueue we have to open the file first and use the resulting fd to register for events
	wd = open(fpath, O_RDONLY);
	if (wd == -1) {
		char errbuf[300];
		sprintf(errbuf, "failed to open file %s for registering with kqueue: %s", fpath, strerror(errno));
		throw std::runtime_error(errbuf);
	}
	_RegisterKqueueFileEvent(wd);
	#endif

	if (wd != -1) {
		Bindable_t* b = new Bindable_t();
		Files.insert(make_pair (wd, b));

		return b->GetBinding();
	}

	throw std::runtime_error("no file watching support on this system"); // is this the right thing to do?
}


/***************************
EventMachine_t::UnwatchFile
***************************/

void EventMachine_t::UnwatchFile (int wd)
{
	Bindable_t *b = Files[wd];
	assert(b);
	Files.erase(wd);

	#ifdef HAVE_INOTIFY
	inotify_rm_watch(inotify->GetSocket(), wd);
	#elif HAVE_KQUEUE
	// With kqueue, closing the monitored fd automatically clears all registered events for it
	close(wd);
	#endif

	if (EventCallback)
		(*EventCallback)(b->GetBinding(), EM_CONNECTION_UNBOUND, NULL, 0);

	delete b;
}

void EventMachine_t::UnwatchFile (const unsigned long sig)
{
	for(map<int, Bindable_t*>::iterator i=Files.begin(); i != Files.end(); i++)
	{
		if (i->second->GetBinding() == sig) {
			UnwatchFile (i->first);
			return;
		}
	}
	throw std::runtime_error("attempted to remove invalid watch signature");
}


/***********************************
EventMachine_t::_ReadInotify_Events
************************************/

void EventMachine_t::_ReadInotifyEvents()
{
	#ifdef HAVE_INOTIFY
	struct inotify_event event;

	assert(EventCallback);

	while (read(inotify->GetSocket(), &event, INOTIFY_EVENT_SIZE) > 0) {
		assert(event.len == 0);
		if (event.mask & IN_MODIFY)
			(*EventCallback)(Files [event.wd]->GetBinding(), EM_CONNECTION_READ, "modified", 8);
		if (event.mask & IN_MOVE_SELF)
			(*EventCallback)(Files [event.wd]->GetBinding(), EM_CONNECTION_READ, "moved", 5);
		if (event.mask & IN_DELETE_SELF) {
			(*EventCallback)(Files [event.wd]->GetBinding(), EM_CONNECTION_READ, "deleted", 7);
			UnwatchFile ((int)event.wd);
		}
	}
	#endif
}


/*************************************
EventMachine_t::_HandleKqueuePidEvent
*************************************/

#ifdef HAVE_KQUEUE
void EventMachine_t::_HandleKqueuePidEvent(struct kevent *event)
{
	assert(EventCallback);

	if (event->fflags & NOTE_FORK)
		(*EventCallback)(Pids [(int) event->ident]->GetBinding(), EM_CONNECTION_READ, "fork", 4);
	if (event->fflags & NOTE_EXIT) {
		(*EventCallback)(Pids [(int) event->ident]->GetBinding(), EM_CONNECTION_READ, "exit", 4);
		// stop watching the pid if it died
		UnwatchPid ((int)event->ident);
	}
}
#endif


/**************************************
EventMachine_t::_HandleKqueueFileEvent
***************************************/

#ifdef HAVE_KQUEUE
void EventMachine_t::_HandleKqueueFileEvent(struct kevent *event)
{
	assert(EventCallback);

	if (event->fflags & NOTE_WRITE)
		(*EventCallback)(Files [(int) event->ident]->GetBinding(), EM_CONNECTION_READ, "modified", 8);
	if (event->fflags & NOTE_RENAME)
		(*EventCallback)(Files [(int) event->ident]->GetBinding(), EM_CONNECTION_READ, "moved", 5);
	if (event->fflags & NOTE_DELETE) {
		(*EventCallback)(Files [(int) event->ident]->GetBinding(), EM_CONNECTION_READ, "deleted", 7);
		UnwatchFile ((int)event->ident);
	}
}
#endif


/****************************************
EventMachine_t::_RegisterKqueueFileEvent
*****************************************/

#ifdef HAVE_KQUEUE
void EventMachine_t::_RegisterKqueueFileEvent(int fd)
{
	struct kevent newevent;
	int kqres;

	// Setup the event with our fd and proper flags
	EV_SET(&newevent, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_DELETE | NOTE_RENAME | NOTE_WRITE, 0, 0);

	// Attempt to register the event
	kqres = kevent(kqfd, &newevent, 1, NULL, 0, NULL);
	if (kqres == -1) {
		char errbuf[200];
		sprintf(errbuf, "failed to register file watch descriptor with kqueue: %s", strerror(errno));
		close(fd);
		throw std::runtime_error(errbuf);
	}
}
#endif


/************************************
EventMachine_t::GetHeartbeatInterval
*************************************/

float EventMachine_t::GetHeartbeatInterval()
{
	return ((float)HeartbeatInterval / 1000000);
}


/************************************
EventMachine_t::SetHeartbeatInterval
*************************************/

int EventMachine_t::SetHeartbeatInterval(float interval)
{
	int iv = (int)(interval * 1000000);
	if (iv > 0) {
		HeartbeatInterval = iv;
		return 1;
	}
	return 0;
}
//#endif // OS_UNIX

