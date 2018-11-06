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

/* The numer of max outstanding timers was once a const enum defined in em.h.
 * Now we define it here so that users can change its value if necessary.
 */
static unsigned int MaxOutstandingTimers = 100000;

/* The number of accept() done at once in a single tick when the acceptor
 * socket becomes readable.
 */
static unsigned int SimultaneousAcceptCount = 10;

/* Internal helper to create a socket with SOCK_CLOEXEC set, and fall
 * back to fcntl'ing it if the headers/runtime don't support it.
 */
SOCKET EmSocket (int domain, int type, int protocol)
{
	SOCKET sd;
#ifdef HAVE_SOCKET_CLOEXEC
	sd = socket (domain, type | SOCK_CLOEXEC, protocol);
	if (sd == INVALID_SOCKET) {
		sd = socket (domain, type, protocol);
		if (sd < 0) {
			return sd;
		}
		SetFdCloexec(sd);
	}
#else
	sd = socket (domain, type, protocol);
	if (sd == INVALID_SOCKET) {
		return sd;
	}
	SetFdCloexec(sd);
#endif
	return sd;
}


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

int EventMachine_t::GetSimultaneousAcceptCount()
{
	return SimultaneousAcceptCount;
}

void EventMachine_t::SetSimultaneousAcceptCount (int count)
{
	if (count < 1)
		count = 1;
	SimultaneousAcceptCount = count;
}


/******************************
EventMachine_t::EventMachine_t
******************************/

EventMachine_t::EventMachine_t (EMCallback event_callback, Poller_t poller):
	NumCloseScheduled (0),
	HeartbeatInterval(2000000),
	EventCallback (event_callback),
	LoopBreakerReader (INVALID_SOCKET),
	LoopBreakerWriter (INVALID_SOCKET),
	bTerminateSignalReceived (false),
	Poller (poller),
	epfd (-1),
	kqfd (-1)
	#ifdef HAVE_INOTIFY
	, inotify (NULL)
	#endif
{
	// Default time-slice is just smaller than one hundred mills.
	Quantum.tv_sec = 0;
	Quantum.tv_usec = 90000;

	// Override the requested poller back to default if needed.
	#if !defined(HAVE_EPOLL) && !defined(HAVE_KQUEUE)
	Poller = Poller_Default;
	#endif

	/* Initialize monotonic timekeeping on OS X before the first call to GetRealTime */
	#ifdef OS_DARWIN
	(void) mach_timebase_info(&mach_timebase);
	#endif

	#ifdef OS_WIN32
	TickCountTickover = 0;
	LastTickCount = 0;
	#endif

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
	SelectData = new SelectData_t();
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
		std::map<int, Bindable_t*>::iterator f = Files.begin();
		UnwatchFile (f->first);
	}

	if (epfd != -1)
		close (epfd);
	if (kqfd != -1)
		close (kqfd);

	delete SelectData;
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
	bTerminateSignalReceived = true;

	/* Signal the loopbreaker so we break out of long-running select/epoll/kqueue and
	 * notice the halt boolean is set. Signalling the loopbreaker also uses a single
	 * signal-safe syscall.
	 */
	SignalLoopBreaker();
}

bool EventMachine_t::Stopping()
{
	return bTerminateSignalReceived;
}

/*******************************
EventMachine_t::SetTimerQuantum
*******************************/

void EventMachine_t::SetTimerQuantum (int interval)
{
	/* We get a timer-quantum expressed in milliseconds.
	 */

	if ((interval < 5) || (interval > 5*60*1000))
		throw std::runtime_error ("invalid timer-quantum");

	Quantum.tv_sec = interval / 1000;
	Quantum.tv_usec = (interval % 1000) * 1000;
}


/*************************************
(STATIC) EventMachine_t::SetuidString
*************************************/

#ifdef OS_UNIX
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

	if (!username || !*username)
		throw std::runtime_error ("setuid_string failed: no username specified");

	errno = 0;
	struct passwd *p = getpwnam (username);
	if (!p) {
		if (errno) {
			char buf[200];
			snprintf (buf, sizeof(buf)-1, "setuid_string failed: %s", strerror(errno));
			throw std::runtime_error (buf);
		} else {
			throw std::runtime_error ("setuid_string failed: unknown username");
		}
	}

	if (setuid (p->pw_uid) != 0)
		throw std::runtime_error ("setuid_string failed: no setuid");

	// Success.
}
#else
void EventMachine_t::SetuidString (const char *username UNUSED) { }
#endif

/****************************************
(STATIC) EventMachine_t::SetRlimitNofile
****************************************/

#ifdef OS_UNIX
int EventMachine_t::SetRlimitNofile (int nofiles)
{
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
}
#else
int EventMachine_t::SetRlimitNofile (int nofiles UNUSED) { return 0; }
#endif

/*********************************
EventMachine_t::SignalLoopBreaker
*********************************/

void EventMachine_t::SignalLoopBreaker()
{
	#ifdef OS_UNIX
	(void)write (LoopBreakerWriter, "", 1);
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
#if defined (HAVE_CLOEXEC) && defined (HAVE_PIPE2)
	int pipestatus = pipe2(fd, O_CLOEXEC);
	if (pipestatus < 0) {
		if (pipe(fd))
			throw std::runtime_error (strerror(errno));
	}
#else
	if (pipe (fd))
		throw std::runtime_error (strerror(errno));
#endif
	if (!SetFdCloexec(fd[0]) || !SetFdCloexec(fd[1]))
		throw std::runtime_error (strerror(errno));

	LoopBreakerWriter = fd[1];
	LoopBreakerReader = fd[0];

	/* 16Jan11: Make sure the pipe is non-blocking, so more than 65k loopbreaks
	 * in one tick do not fill up the pipe and block the process on write() */
	SetSocketNonblocking (LoopBreakerWriter);
	#endif

	#ifdef OS_WIN32
	SOCKET sd = EmSocket (AF_INET, SOCK_DGRAM, 0);
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

	#ifdef HAVE_EPOLL
	if (Poller == Poller_Epoll) {
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
	if (Poller == Poller_Kqueue) {
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
}

/***************************
EventMachine_t::_UpdateTime
***************************/

void EventMachine_t::_UpdateTime()
{
	MyCurrentLoopTime = GetRealTime();
}

/***************************
EventMachine_t::GetRealTime
***************************/

// Two great writeups of cross-platform monotonic time are at:
// http://www.python.org/dev/peps/pep-0418
// http://nadeausoftware.com/articles/2012/04/c_c_tip_how_measure_elapsed_real_time_benchmarking
// Uncomment the #pragma messages to confirm which compile-time option was used
uint64_t EventMachine_t::GetRealTime()
{
	uint64_t current_time;

	#if defined(HAVE_CONST_CLOCK_MONOTONIC_RAW)
	// #pragma message "GetRealTime: clock_gettime CLOCK_MONOTONIC_RAW"
	// Linux 2.6.28 and above
	struct timespec tv;
	clock_gettime (CLOCK_MONOTONIC_RAW, &tv);
	current_time = (((uint64_t)(tv.tv_sec)) * 1000000LL) + ((uint64_t)((tv.tv_nsec)/1000));

	#elif defined(HAVE_CONST_CLOCK_MONOTONIC)
	// #pragma message "GetRealTime: clock_gettime CLOCK_MONOTONIC"
	// Linux, FreeBSD 5.0 and above, Solaris 8 and above, OpenBSD, NetBSD, DragonflyBSD
	struct timespec tv;
	clock_gettime (CLOCK_MONOTONIC, &tv);
	current_time = (((uint64_t)(tv.tv_sec)) * 1000000LL) + ((uint64_t)((tv.tv_nsec)/1000));

	#elif defined(HAVE_GETHRTIME)
	// #pragma message "GetRealTime: gethrtime"
	// Solaris and HP-UX
	current_time = (uint64_t)gethrtime() / 1000;

	#elif defined(OS_DARWIN)
	// #pragma message "GetRealTime: mach_absolute_time"
	// Mac OS X
	// https://developer.apple.com/library/mac/qa/qa1398/_index.html
	current_time = mach_absolute_time() * mach_timebase.numer / mach_timebase.denom / 1000;

	#elif defined(OS_UNIX)
	// #pragma message "GetRealTime: gettimeofday"
	// Unix fallback
	struct timeval tv;
	gettimeofday (&tv, NULL);
	current_time = (((uint64_t)(tv.tv_sec)) * 1000000LL) + ((uint64_t)(tv.tv_usec));

	#elif defined(OS_WIN32)
	// #pragma message "GetRealTime: GetTickCount"
	// Future improvement: use GetTickCount64 in Windows Vista / Server 2008
	unsigned tick = GetTickCount();
	if (tick < LastTickCount)
		TickCountTickover += 1;
	LastTickCount = tick;
	current_time = ((uint64_t)TickCountTickover << 32) + (uint64_t)tick;
	current_time *= 1000; // convert to microseconds

	#else
	// #pragma message "GetRealTime: time"
	// Universal fallback
	current_time = (uint64_t)time(NULL) * 1000000LL;
	#endif

	return current_time;
}

/***********************************
EventMachine_t::_DispatchHeartbeats
***********************************/

void EventMachine_t::_DispatchHeartbeats()
{
	// Store the first processed heartbeat descriptor and bail out if
	// we see it again. This fixes an infinite loop in case the system time
	// is changed out from underneath MyCurrentLoopTime.
	const EventableDescriptor *head = NULL;

	while (true) {
		std::multimap<uint64_t,EventableDescriptor*>::iterator i = Heartbeats.begin();
		if (i == Heartbeats.end())
			break;
		if (i->first > MyCurrentLoopTime)
			break;

		EventableDescriptor *ed = i->second;
		if (ed == head)
			break;

		ed->Heartbeat();
		QueueHeartbeat(ed);

		if (head == NULL)
			head = ed;
	}
}

/******************************
EventMachine_t::QueueHeartbeat
******************************/

void EventMachine_t::QueueHeartbeat(EventableDescriptor *ed)
{
	uint64_t heartbeat = ed->GetNextHeartbeat();

	if (heartbeat) {
		#ifndef HAVE_MAKE_PAIR
		Heartbeats.insert (std::multimap<uint64_t,EventableDescriptor*>::value_type (heartbeat, ed));
		#else
		Heartbeats.insert (std::make_pair (heartbeat, ed));
		#endif
	}
}

/******************************
EventMachine_t::ClearHeartbeat
******************************/

void EventMachine_t::ClearHeartbeat(uint64_t key, EventableDescriptor* ed)
{
	std::multimap<uint64_t,EventableDescriptor*>::iterator it;
	std::pair<std::multimap<uint64_t,EventableDescriptor*>::iterator,std::multimap<uint64_t,EventableDescriptor*>::iterator> ret;
	ret = Heartbeats.equal_range (key);
	for (it = ret.first; it != ret.second; ++it) {
		if (it->second == ed) {
			Heartbeats.erase (it);
			break;
		}
	}
}

/*******************
EventMachine_t::Run
*******************/

void EventMachine_t::Run()
{
	while (RunOnce()) ;
}

/***********************
EventMachine_t::RunOnce
***********************/

bool EventMachine_t::RunOnce()
{
	_UpdateTime();
	_RunTimers();

	/* _Add must precede _Modify because the same descriptor might
	 * be on both lists during the same pass through the machine,
	 * and to modify a descriptor before adding it would fail.
	 */
	_AddNewDescriptors();
	_ModifyDescriptors();

	switch (Poller) {
	case Poller_Epoll:
		_RunEpollOnce();
		break;
	case Poller_Kqueue:
		_RunKqueueOnce();
		break;
	case Poller_Default:
		_RunSelectOnce();
		break;
	}

	_DispatchHeartbeats();
	_CleanupSockets();

	if (bTerminateSignalReceived)
		return false;

	return true;
}


/*****************************
EventMachine_t::_RunEpollOnce
*****************************/

void EventMachine_t::_RunEpollOnce()
{
	#ifdef HAVE_EPOLL
	assert (epfd != -1);
	int s;

	timeval tv = _TimeTilNextEvent();

	#ifdef BUILD_FOR_RUBY
	int ret = 0;

	#ifdef HAVE_RB_WAIT_FOR_SINGLE_FD
	if ((ret = rb_wait_for_single_fd(epfd, RB_WAITFD_IN|RB_WAITFD_PRI, &tv)) < 1) {
	#else
	fd_set fdreads;

	FD_ZERO(&fdreads);
	FD_SET(epfd, &fdreads);

	if ((ret = rb_thread_select(epfd + 1, &fdreads, NULL, NULL, &tv)) < 1) {
	#endif
		if (ret == -1) {
			assert(errno != EINVAL);
			assert(errno != EBADF);
		}
		return;
	}

	TRAP_BEG;
	s = epoll_wait (epfd, epoll_events, MaxEvents, 0);
	TRAP_END;
	#else
	int duration = 0;
	duration = duration + (tv.tv_sec * 1000);
	duration = duration + (tv.tv_usec / 1000);
	s = epoll_wait (epfd, epoll_events, MaxEvents, duration);
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
	#else
	throw std::runtime_error ("epoll is not implemented on this platform");
	#endif
}


/******************************
EventMachine_t::_RunKqueueOnce
******************************/

#ifdef HAVE_KQUEUE
void EventMachine_t::_RunKqueueOnce()
{
	assert (kqfd != -1);
	int k;

	timeval tv = _TimeTilNextEvent();

	struct timespec ts;
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;

	#ifdef BUILD_FOR_RUBY
	int ret = 0;

	#ifdef HAVE_RB_WAIT_FOR_SINGLE_FD
	if ((ret = rb_wait_for_single_fd(kqfd, RB_WAITFD_IN|RB_WAITFD_PRI, &tv)) < 1) {
	#else
	fd_set fdreads;

	FD_ZERO(&fdreads);
	FD_SET(kqfd, &fdreads);

	if ((ret = rb_thread_select(kqfd + 1, &fdreads, NULL, NULL, &tv)) < 1) {
	#endif
		if (ret == -1) {
			assert(errno != EINVAL);
			assert(errno != EBADF);
		}
		return;
	}

	TRAP_BEG;
	ts.tv_sec = ts.tv_nsec = 0;
	k = kevent (kqfd, NULL, 0, Karray, MaxEvents, &ts);
	TRAP_END;
	#else
	k = kevent (kqfd, NULL, 0, Karray, MaxEvents, &ts);
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
					std::cerr << "Discarding unknown kqueue event " << ke->filter << std::endl;

				break;
		}

		--k;
		++ke;
	}

	// TODO, replace this with rb_thread_blocking_region for 1.9 builds.
	#ifdef BUILD_FOR_RUBY
	if (!rb_thread_alone()) {
		rb_thread_schedule();
	}
	#endif
}
#else
void EventMachine_t::_RunKqueueOnce()
{
	throw std::runtime_error ("kqueue is not implemented on this platform");
}
#endif


/*********************************
EventMachine_t::_TimeTilNextEvent
*********************************/

timeval EventMachine_t::_TimeTilNextEvent()
{
	// 29jul11: Changed calculation base from MyCurrentLoopTime to the
	// real time. As MyCurrentLoopTime is set at the beginning of an
	// iteration and this calculation is done at the end, evenmachine
	// will potentially oversleep by the amount of time the iteration
	// took to execute.
	uint64_t next_event = 0;
	uint64_t current_time = GetRealTime();

	if (!Heartbeats.empty()) {
		std::multimap<uint64_t,EventableDescriptor*>::iterator heartbeats = Heartbeats.begin();
		next_event = heartbeats->first;
	}

	if (!Timers.empty()) {
		std::multimap<uint64_t,Timer_t>::iterator timers = Timers.begin();
		if (next_event == 0 || timers->first < next_event)
			next_event = timers->first;
	}

	if (!NewDescriptors.empty() || !ModifiedDescriptors.empty()) {
		next_event = current_time;
	}

	timeval tv;

	if (NumCloseScheduled > 0 || bTerminateSignalReceived) {
		tv.tv_sec = tv.tv_usec = 0;
	} else if (next_event == 0) {
		tv = Quantum;
	} else {
		if (next_event > current_time) {
			uint64_t duration = next_event - current_time;
			tv.tv_sec = duration / 1000000;
			tv.tv_usec = duration % 1000000;
		} else {
			tv.tv_sec = tv.tv_usec = 0;
		}
	}

	return tv;
}

/*******************************
EventMachine_t::_CleanupSockets
*******************************/

void EventMachine_t::_CleanupSockets()
{
	// TODO, rip this out and only delete the descriptors we know have died,
	// rather than traversing the whole list.
	// Modified 05Jan08 per suggestions by Chris Heath. It's possible that
	// an EventableDescriptor will have a descriptor value of -1. That will
	// happen if EventableDescriptor::Close was called on it. In that case,
	// don't call epoll_ctl to remove the socket's filters from the epoll set.
	// According to the epoll docs, this happens automatically when the
	// descriptor is closed anyway. This is different from the case where
	// the socket has already been closed but the descriptor in the ED object
	// hasn't yet been set to INVALID_SOCKET.
	// In kqueue, closing a descriptor automatically removes its event filters.
	int i, j;
	int nSockets = Descriptors.size();
	for (i=0, j=0; i < nSockets; i++) {
		EventableDescriptor *ed = Descriptors[i];
		assert (ed);
		if (ed->ShouldDelete()) {
		#ifdef HAVE_EPOLL
			if (Poller == Poller_Epoll) {
				assert (epfd != -1);
				if (ed->GetSocket() != INVALID_SOCKET) {
					int e = epoll_ctl (epfd, EPOLL_CTL_DEL, ed->GetSocket(), ed->GetEpollEvent());
					// ENOENT or EBADF are not errors because the socket may be already closed when we get here.
					if (e && (errno != ENOENT) && (errno != EBADF) && (errno != EPERM)) {
						char buf [200];
						snprintf (buf, sizeof(buf)-1, "unable to delete epoll event: %s", strerror(errno));
						throw std::runtime_error (buf);
					}
				}
				ModifiedDescriptors.erase(ed);
			}
		#endif
			delete ed;
		}
		else
			Descriptors [j++] = ed;
	}
	while ((size_t)j < Descriptors.size())
		Descriptors.pop_back();
}

/*********************************
EventMachine_t::_ModifyEpollEvent
*********************************/

#ifdef HAVE_EPOLL
void EventMachine_t::_ModifyEpollEvent (EventableDescriptor *ed)
{
	if (Poller == Poller_Epoll) {
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
}
#else
void EventMachine_t::_ModifyEpollEvent (EventableDescriptor *ed UNUSED) { }
#endif


/**************************
SelectData_t::SelectData_t
**************************/

SelectData_t::SelectData_t()
{
	maxsocket = 0;
	rb_fd_init (&fdreads);
	rb_fd_init (&fdwrites);
	rb_fd_init (&fderrors);
}

SelectData_t::~SelectData_t()
{
	rb_fd_term (&fdreads);
	rb_fd_term (&fdwrites);
	rb_fd_term (&fderrors);
}

#ifdef BUILD_FOR_RUBY
/*****************
_SelectDataSelect
*****************/

#if defined(HAVE_RB_THREAD_BLOCKING_REGION) || defined(HAVE_RB_THREAD_CALL_WITHOUT_GVL)
static VALUE _SelectDataSelect (void *v)
{
	SelectData_t *sd = (SelectData_t*)v;
	sd->nSockets = rb_fd_select (sd->maxsocket+1, &(sd->fdreads), &(sd->fdwrites), &(sd->fderrors), &(sd->tv));
	return Qnil;
}
#endif

/*********************
SelectData_t::_Select
*********************/

int SelectData_t::_Select()
{
	#if defined(HAVE_RB_THREAD_CALL_WITHOUT_GVL)
	// added in ruby 1.9.3
	rb_thread_call_without_gvl ((void *(*)(void *))_SelectDataSelect, (void*)this, RUBY_UBF_IO, 0);
	return nSockets;
	#elif defined(HAVE_TBR)
	// added in ruby 1.9.1, deprecated in ruby 2.0.0
	rb_thread_blocking_region (_SelectDataSelect, (void*)this, RUBY_UBF_IO, 0);
	return nSockets;
	#else
	return EmSelect (maxsocket+1, &fdreads, &fdwrites, &fderrors, &tv);
	#endif
}
#endif

void SelectData_t::_Clear()
{
	maxsocket = 0;
	rb_fd_zero (&fdreads);
	rb_fd_zero (&fdwrites);
	rb_fd_zero (&fderrors);
}

/******************************
EventMachine_t::_RunSelectOnce
******************************/

void EventMachine_t::_RunSelectOnce()
{
	// Crank the event machine once.
	// If there are no descriptors to process, then sleep
	// for a few hundred mills to avoid busy-looping.
	// This is based on a select loop. Alternately provide epoll
	// if we know we're running on a 2.6 kernel.
	// epoll will be effective if we provide it as an alternative,
	// however it has the same problem interoperating with Ruby
	// threads that select does.

	// Get ready for select()
	SelectData->_Clear();

	// Always read the loop-breaker reader.
	// Changed 23Aug06, provisionally implemented for Windows with a UDP socket
	// running on localhost with a randomly-chosen port. (*Puke*)
	// Windows has a version of the Unix pipe() library function, but it doesn't
	// give you back descriptors that are selectable.
	rb_fd_set (LoopBreakerReader, &(SelectData->fdreads));
	if (SelectData->maxsocket < LoopBreakerReader)
		SelectData->maxsocket = LoopBreakerReader;

	// prepare the sockets for reading and writing
	size_t i;
	for (i = 0; i < Descriptors.size(); i++) {
		EventableDescriptor *ed = Descriptors[i];
		assert (ed);
		SOCKET sd = ed->GetSocket();
		if (ed->IsWatchOnly() && sd == INVALID_SOCKET)
			continue;
		assert (sd != INVALID_SOCKET);

		if (ed->SelectForRead())
			rb_fd_set (sd, &(SelectData->fdreads));
		if (ed->SelectForWrite())
			rb_fd_set (sd, &(SelectData->fdwrites));

		#ifdef OS_WIN32
		/* 21Sep09: on windows, a non-blocking connect() that fails does not come up as writable.
		   Instead, it is added to the error set. See http://www.mail-archive.com/openssl-users@openssl.org/msg58500.html
		*/
		if (ed->IsConnectPending())
			rb_fd_set (sd, &(SelectData->fderrors));
		#endif

		if (SelectData->maxsocket < sd)
			SelectData->maxsocket = sd;
	}


	{ // read and write the sockets
		//timeval tv = {1, 0}; // Solaris fails if the microseconds member is >= 1000000.
		//timeval tv = Quantum;
		SelectData->tv = _TimeTilNextEvent();
		int s = SelectData->_Select();
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
				SOCKET sd = ed->GetSocket();
				if (ed->IsWatchOnly() && sd == INVALID_SOCKET)
					continue;
				assert (sd != INVALID_SOCKET);

				if (rb_fd_isset (sd, &(SelectData->fdwrites))) {
					// Double-check SelectForWrite() still returns true. If not, one of the callbacks must have
					// modified some value since we checked SelectForWrite() earlier in this method.
					if (ed->SelectForWrite())
						ed->Write();
				}
				if (rb_fd_isset (sd, &(SelectData->fdreads)))
					ed->Read();
				if (rb_fd_isset (sd, &(SelectData->fderrors)))
					ed->HandleError();
			}

			if (rb_fd_isset (LoopBreakerReader, &(SelectData->fdreads)))
				_ReadLoopBreaker();
		}
		else if (s < 0) {
			switch (errno) {
				case EBADF:
					_CleanBadDescriptors();
					break;
				case EINVAL:
					throw std::runtime_error ("Somehow EM passed an invalid nfds or invalid timeout to select(2), please report this!");
					break;
				default:
					// select can fail on error in a handful of ways.
					// If this happens, then wait for a little while to avoid busy-looping.
					// If the error was EINTR, we probably caught SIGCHLD or something,
					// so keep the wait short.
					timeval tv = {0, ((errno == EINTR) ? 5 : 50) * 1000};
					EmSelect (0, NULL, NULL, NULL, &tv);
			}
		}
	}
}

void EventMachine_t::_CleanBadDescriptors()
{
	size_t i;

	for (i = 0; i < Descriptors.size(); i++) {
		EventableDescriptor *ed = Descriptors[i];
		if (ed->ShouldDelete())
			continue;

		SOCKET sd = ed->GetSocket();

		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 0;

		rb_fdset_t fds;
		rb_fd_init(&fds);
		rb_fd_set(sd, &fds);

		int ret = rb_fd_select(sd + 1, &fds, NULL, NULL, &tv);
		rb_fd_term(&fds);

		if (ret == -1) {
			if (errno == EBADF)
				ed->ScheduleClose(false);
		}
	}
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
	(void)read (LoopBreakerReader, buffer, sizeof(buffer));
	if (EventCallback)
		(*EventCallback)(0, EM_LOOPBREAK_SIGNAL, "", 0);
}


/**************************
EventMachine_t::_RunTimers
**************************/

void EventMachine_t::_RunTimers()
{
	// These are caller-defined timer handlers.
	// We rely on the fact that multimaps sort by their keys to avoid
	// inspecting the whole list every time we come here.
	// Just keep inspecting and processing the list head until we hit
	// one that hasn't expired yet.

	while (true) {
		std::multimap<uint64_t,Timer_t>::iterator i = Timers.begin();
		if (i == Timers.end())
			break;
		if (i->first > MyCurrentLoopTime)
			break;
		if (EventCallback)
			(*EventCallback) (0, EM_TIMER_FIRED, NULL, i->second.GetBinding());
		Timers.erase (i);
	}
}



/***********************************
EventMachine_t::InstallOneshotTimer
***********************************/

const uintptr_t EventMachine_t::InstallOneshotTimer (uint64_t milliseconds)
{
	if (Timers.size() > MaxOutstandingTimers)
		return false;

	uint64_t fire_at = GetRealTime();
	fire_at += ((uint64_t)milliseconds) * 1000LL;

	Timer_t t;
	#ifndef HAVE_MAKE_PAIR
	std::multimap<uint64_t,Timer_t>::iterator i = Timers.insert (std::multimap<uint64_t,Timer_t>::value_type (fire_at, t));
	#else
	std::multimap<uint64_t,Timer_t>::iterator i = Timers.insert (std::make_pair (fire_at, t));
	#endif
	return i->second.GetBinding();
}


/*******************************
EventMachine_t::ConnectToServer
*******************************/

const uintptr_t EventMachine_t::ConnectToServer (const char *bind_addr, int bind_port, const char *server, int port)
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

	struct sockaddr_storage bind_as;
	size_t bind_as_len = sizeof bind_as;
	int gai = name2address (server, port, SOCK_STREAM, (struct sockaddr *)&bind_as, &bind_as_len);
	if (gai != 0) {
		char buf [200];
		snprintf (buf, sizeof(buf)-1, "unable to resolve address: %s", gai_strerror(gai));
		throw std::runtime_error (buf);
	}

	SOCKET sd = EmSocket (bind_as.ss_family, SOCK_STREAM, 0);
	if (sd == INVALID_SOCKET) {
		char buf [200];
		snprintf (buf, sizeof(buf)-1, "unable to create new socket: %s", strerror(errno));
		throw std::runtime_error (buf);
	}

	// From here on, ALL error returns must close the socket.
	// Set the new socket nonblocking.
	if (!SetSocketNonblocking (sd)) {
		close (sd);
		throw std::runtime_error ("unable to set socket as non-blocking");
	}
	// Disable slow-start (Nagle algorithm).
	int one = 1;
	setsockopt (sd, IPPROTO_TCP, TCP_NODELAY, (char*) &one, sizeof(one));
	// Set reuseaddr to improve performance on restarts
	setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, (char*) &one, sizeof(one));

	if (bind_addr) {
		struct sockaddr_storage bind_to;
		size_t bind_to_len = sizeof bind_to;
		gai = name2address (bind_addr, bind_port, SOCK_STREAM, (struct sockaddr *)&bind_to, &bind_to_len);
		if (gai != 0) {
			close (sd);
			char buf [200];
			snprintf (buf, sizeof(buf)-1, "invalid bind address: %s", gai_strerror(gai));
			throw std::runtime_error (buf);
		}
		if (bind (sd, (struct sockaddr *)&bind_to, bind_to_len) < 0) {
			close (sd);
			throw std::runtime_error ("couldn't bind to address");
		}
	}

	uintptr_t out = 0;

	#ifdef OS_UNIX
	int e_reason = 0;
	if (connect (sd, (struct sockaddr *)&bind_as, bind_as_len) == 0) {
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
		int error = 0;
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
		} else {
			// Fall through to the !out case below.
			e_reason = error;
		}
	}
	else {
		// The error from connect was something other then EINPROGRESS (EHOSTDOWN, etc).
		// Fall through to the !out case below
		e_reason = errno;
	}

	if (!out) {
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
		cd->SetUnbindReasonCode (e_reason);
		cd->ScheduleClose (false);
		Add (cd);
		out = cd->GetBinding();
	}
	#endif

	#ifdef OS_WIN32
	if (connect (sd, (struct sockaddr *)&bind_as, bind_as_len) == 0) {
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
		close (sd);
	return out;
}

/***********************************
EventMachine_t::ConnectToUnixServer
***********************************/

#ifdef OS_UNIX
const uintptr_t EventMachine_t::ConnectToUnixServer (const char *server)
{
	/* Connect to a Unix-domain server, which by definition is running
	 * on the same host.
	 * There is no meaningful implementation on Windows.
	 * There's no need to do a nonblocking connect, since the connection
	 * is always local and can always be fulfilled immediately.
	 */

	uintptr_t out = 0;

	if (!server || !*server)
		return 0;

	sockaddr_un pun;
	memset (&pun, 0, sizeof(pun));
	pun.sun_family = AF_LOCAL;

	// You ordinarily expect the server name field to be at least 1024 bytes long,
	// but on Linux it can be MUCH shorter.
	if (strlen(server) >= sizeof(pun.sun_path))
		throw std::runtime_error ("unix-domain server name is too long");


	strcpy (pun.sun_path, server);

	SOCKET fd = EmSocket (AF_LOCAL, SOCK_STREAM, 0);
	if (fd == INVALID_SOCKET)
		return 0;

	// From here on, ALL error returns must close the socket.
	// NOTE: At this point, the socket is still a blocking socket.
	if (connect (fd, (struct sockaddr*)&pun, sizeof(pun)) != 0) {
		close (fd);
		return 0;
	}

	// Set the newly-connected socket nonblocking.
	if (!SetSocketNonblocking (fd)) {
		close (fd);
		return 0;
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
		close (fd);

	return out;
}
#else
const uintptr_t EventMachine_t::ConnectToUnixServer (const char *server UNUSED)
{
	throw std::runtime_error ("unix-domain connection unavailable on this platform");
}
#endif

/************************
EventMachine_t::AttachFD
************************/

const uintptr_t EventMachine_t::AttachFD (SOCKET fd, bool watch_mode)
{
	#ifdef OS_UNIX
	if (fcntl(fd, F_GETFL, 0) < 0) {
		if (errno) {
			throw std::runtime_error (strerror(errno));
		} else {
			throw std::runtime_error ("invalid file descriptor");
		}
	}
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

	cd->SetAttached(true);
	cd->SetWatchOnly(watch_mode);
	cd->SetConnectPending (false);

	Add (cd);

	const uintptr_t out = cd->GetBinding();
	return out;
}

/************************
EventMachine_t::DetachFD
************************/

int EventMachine_t::DetachFD (EventableDescriptor *ed)
{
	if (!ed)
		throw std::runtime_error ("detaching bad descriptor");

	SOCKET fd = ed->GetSocket();

	#ifdef HAVE_EPOLL
	if (Poller == Poller_Epoll) {
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
	if (Poller == Poller_Kqueue) {
		// remove any read/write events for this fd
		struct kevent k;
#ifdef __NetBSD__
		EV_SET (&k, ed->GetSocket(), EVFILT_READ | EVFILT_WRITE, EV_DELETE, 0, 0, (intptr_t)ed);
#else
		EV_SET (&k, ed->GetSocket(), EVFILT_READ | EVFILT_WRITE, EV_DELETE, 0, 0, ed);
#endif
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

	// Prevent the descriptor from being added, in case DetachFD was called in the same tick as AttachFD
	for (size_t i = 0; i < NewDescriptors.size(); i++) {
		if (ed == NewDescriptors[i]) {
			NewDescriptors.erase(NewDescriptors.begin() + i);
			break;
		}
	}

	// Set MySocket = INVALID_SOCKET so ShouldDelete() is true (and the descriptor gets deleted and removed),
	// and also to prevent anyone from calling close() on the detached fd
	ed->SetSocketInvalid();

	return fd;
}

/************
name2address
************/

int EventMachine_t::name2address (const char *server, int port, int socktype, struct sockaddr *addr, size_t *addr_len)
{
	if (!server || !*server)
		server = "0.0.0.0";

	struct addrinfo *ai;
	struct addrinfo hints;
	memset (&hints, 0, sizeof(hints));
	hints.ai_socktype = socktype;
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;

	char portstr[12];
	snprintf(portstr, sizeof(portstr), "%u", port);

	int gai = getaddrinfo (server, portstr, &hints, &ai);
	if (gai == 0) {
		assert (ai->ai_addrlen <= *addr_len);
		memcpy (addr, ai->ai_addr, ai->ai_addrlen);
		*addr_len = ai->ai_addrlen;
		freeaddrinfo(ai);
	}

	return gai;
}


/*******************************
EventMachine_t::CreateTcpServer
*******************************/

const uintptr_t EventMachine_t::CreateTcpServer (const char *server, int port)
{
	/* Create a TCP-acceptor (server) socket and add it to the event machine.
	 * Return the binding of the new acceptor to the caller.
	 * This binding will be referenced when the new acceptor sends events
	 * to indicate accepted connections.
	 */


	struct sockaddr_storage bind_here;
	size_t bind_here_len = sizeof bind_here;
	if (0 != name2address (server, port, SOCK_STREAM, (struct sockaddr *)&bind_here, &bind_here_len))
		return 0;

	SOCKET sd_accept = EmSocket (bind_here.ss_family, SOCK_STREAM, 0);
	if (sd_accept == INVALID_SOCKET) {
		goto fail;
	}

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


	if (bind (sd_accept, (struct sockaddr *)&bind_here, bind_here_len)) {
		//__warning ("binding failed");
		goto fail;
	}

	if (listen (sd_accept, 100)) {
		//__warning ("listen failed");
		goto fail;
	}

	return AttachSD(sd_accept);

	fail:
	if (sd_accept != INVALID_SOCKET)
		close (sd_accept);
	return 0;
}


/**********************************
EventMachine_t::OpenDatagramSocket
**********************************/

const uintptr_t EventMachine_t::OpenDatagramSocket (const char *address, int port)
{
	uintptr_t output_binding = 0;

	struct sockaddr_storage bind_here;
	size_t bind_here_len = sizeof bind_here;
	if (0 != name2address (address, port, SOCK_DGRAM, (struct sockaddr *)&bind_here, &bind_here_len))
		return 0;

	// from here on, early returns must close the socket!
	SOCKET sd = EmSocket (bind_here.ss_family, SOCK_DGRAM, 0);
	if (sd == INVALID_SOCKET)
		goto fail;

	{ // set the SO_REUSEADDR on the socket before we bind, otherwise it won't work for a second one
		int oval = 1;
		if (setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, (char*)&oval, sizeof(oval)) < 0)
			goto fail;
	}

	// Set the new socket nonblocking.
	if (!SetSocketNonblocking (sd))
		goto fail;

	if (bind (sd, (struct sockaddr *)&bind_here, bind_here_len) != 0)
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
		close (sd);
	return 0;
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

#ifdef HAVE_KQUEUE
void EventMachine_t::ArmKqueueWriter (EventableDescriptor *ed)
{
	if (Poller == Poller_Kqueue) {
		if (!ed)
			throw std::runtime_error ("added bad descriptor");
		struct kevent k;
#ifdef __NetBSD__
		EV_SET (&k, ed->GetSocket(), EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, (intptr_t)ed);
#else
		EV_SET (&k, ed->GetSocket(), EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, ed);
#endif
		int t = kevent (kqfd, &k, 1, NULL, 0, NULL);
		if (t < 0) {
			char buf [200];
			snprintf (buf, sizeof(buf)-1, "arm kqueue writer failed on %d: %s", ed->GetSocket(), strerror(errno));
			throw std::runtime_error (buf);
		}
	}
}
#else
void EventMachine_t::ArmKqueueWriter (EventableDescriptor *ed UNUSED) { }
#endif

/*******************************
EventMachine_t::ArmKqueueReader
*******************************/

#ifdef HAVE_KQUEUE
void EventMachine_t::ArmKqueueReader (EventableDescriptor *ed)
{
	if (Poller == Poller_Kqueue) {
		if (!ed)
			throw std::runtime_error ("added bad descriptor");
		struct kevent k;
#ifdef __NetBSD__
		EV_SET (&k, ed->GetSocket(), EVFILT_READ, EV_ADD, 0, 0, (intptr_t)ed);
#else
		EV_SET (&k, ed->GetSocket(), EVFILT_READ, EV_ADD, 0, 0, ed);
#endif
		int t = kevent (kqfd, &k, 1, NULL, 0, NULL);
		if (t < 0) {
			char buf [200];
			snprintf (buf, sizeof(buf)-1, "arm kqueue reader failed on %d: %s", ed->GetSocket(), strerror(errno));
			throw std::runtime_error (buf);
		}
	}
}
#else
void EventMachine_t::ArmKqueueReader (EventableDescriptor *ed UNUSED) { }
#endif

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
		if (Poller == Poller_Epoll) {
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
		if (Poller == Poller_Kqueue) {
			// INCOMPLETE. Some descriptors don't want to be readable.
			assert (kqfd != -1);
			struct kevent k;
#ifdef __NetBSD__
			EV_SET (&k, ed->GetSocket(), EVFILT_READ, EV_ADD, 0, 0, (intptr_t)ed);
#else
			EV_SET (&k, ed->GetSocket(), EVFILT_READ, EV_ADD, 0, 0, ed);
#endif
			int t = kevent (kqfd, &k, 1, NULL, 0, NULL);
			assert (t == 0);
		}
		*/
		#endif

		QueueHeartbeat(ed);
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
	if (Poller == Poller_Epoll) {
		std::set<EventableDescriptor*>::iterator i = ModifiedDescriptors.begin();
		while (i != ModifiedDescriptors.end()) {
			assert (*i);
			_ModifyEpollEvent (*i);
			++i;
		}
	}
	#endif

	#ifdef HAVE_KQUEUE
	if (Poller == Poller_Kqueue) {
		std::set<EventableDescriptor*>::iterator i = ModifiedDescriptors.begin();
		while (i != ModifiedDescriptors.end()) {
			assert (*i);
			if ((*i)->GetKqueueArmWrite())
				ArmKqueueWriter (*i);
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


/***********************
EventMachine_t::Deregister
***********************/

void EventMachine_t::Deregister (EventableDescriptor *ed)
{
	if (!ed)
		throw std::runtime_error ("modified bad descriptor");
	#ifdef HAVE_EPOLL
	// cut/paste from _CleanupSockets().  The error handling could be
	// refactored out of there, but it is cut/paste all over the
	// file already.
	if (Poller == Poller_Epoll) {
		assert (epfd != -1);
		assert (ed->GetSocket() != INVALID_SOCKET);
		int e = epoll_ctl (epfd, EPOLL_CTL_DEL, ed->GetSocket(), ed->GetEpollEvent());
		// ENOENT or EBADF are not errors because the socket may be already closed when we get here.
		if (e && (errno != ENOENT) && (errno != EBADF) && (errno != EPERM)) {
			char buf [200];
			snprintf (buf, sizeof(buf)-1, "unable to delete epoll event: %s", strerror(errno));
			throw std::runtime_error (buf);
		}
		ModifiedDescriptors.erase(ed);
	}
	#endif

	#ifdef HAVE_KQUEUE
	if (Poller == Poller_Kqueue) {
		assert (ed->GetSocket() != INVALID_SOCKET);

		ModifiedDescriptors.erase(ed);
	}
	#endif
}


/**************************************
EventMachine_t::CreateUnixDomainServer
**************************************/

#ifdef OS_UNIX
const uintptr_t EventMachine_t::CreateUnixDomainServer (const char *filename)
{
	/* Create a UNIX-domain acceptor (server) socket and add it to the event machine.
	 * Return the binding of the new acceptor to the caller.
	 * This binding will be referenced when the new acceptor sends events
	 * to indicate accepted connections.
	 * THERE IS NO MEANINGFUL IMPLEMENTATION ON WINDOWS.
	 */

	struct sockaddr_un s_sun;

	SOCKET sd_accept = EmSocket (AF_LOCAL, SOCK_STREAM, 0);
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

	return AttachSD(sd_accept);

	fail:
	if (sd_accept != INVALID_SOCKET)
		close (sd_accept);
	return 0;
}
#else
const uintptr_t EventMachine_t::CreateUnixDomainServer (const char *filename UNUSED)
{
	throw std::runtime_error ("unix-domain server unavailable on this platform");
}
#endif


/**************************************
EventMachine_t::AttachSD
**************************************/

const uintptr_t EventMachine_t::AttachSD (SOCKET sd_accept)
{
	uintptr_t output_binding = 0;

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
		close (sd_accept);
	return 0;
}


/**************************
EventMachine_t::Socketpair
**************************/

#ifdef OS_UNIX
const uintptr_t EventMachine_t::Socketpair (char * const * cmd_strings)
{
	// Make sure the incoming array of command strings is sane.
	if (!cmd_strings)
		return 0;
	int j;
	for (j=0; j < 2048 && cmd_strings[j]; j++)
		;
	if ((j==0) || (j==2048))
		return 0;

	uintptr_t output_binding = 0;

	int sv[2];
	if (socketpair (AF_LOCAL, SOCK_STREAM, 0, sv) < 0)
		return 0;
	// from here, all early returns must close the pair of sockets.

	// Set the parent side of the socketpair nonblocking.
	// We don't care about the child side, and most child processes will expect their
	// stdout to be blocking. Thanks to Duane Johnson and Bill Kelly for pointing this out.
	// Obviously DON'T set CLOEXEC.
	if (!SetSocketNonblocking (sv[0])) {
		close (sv[0]);
		close (sv[1]);
		return 0;
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
}
#else
const uintptr_t EventMachine_t::Socketpair (char * const * cmd_strings UNUSED)
{
	throw std::runtime_error ("socketpair is currently unavailable on this platform");
}
#endif



/****************************
EventMachine_t::OpenKeyboard
****************************/

const uintptr_t EventMachine_t::OpenKeyboard()
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
	int i = 0;
	// Subtract one for epoll or kqueue because of the LoopbreakDescriptor
	if (Poller == Poller_Epoll || Poller == Poller_Kqueue)
		i = 1;

	return Descriptors.size() + NewDescriptors.size() - i;
}


/************************
EventMachine_t::WatchPid
************************/

#ifdef HAVE_KQUEUE
const uintptr_t EventMachine_t::WatchPid (int pid)
{
	if (Poller != Poller_Kqueue)
		throw std::runtime_error("must enable kqueue (EM.kqueue=true) for pid watching support");

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
	Bindable_t* b = new Bindable_t();
	Pids.insert(std::make_pair (pid, b));

	return b->GetBinding();
}
#else
const uintptr_t EventMachine_t::WatchPid (int pid UNUSED)
{
	throw std::runtime_error("no pid watching support on this system");
}
#endif

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

void EventMachine_t::UnwatchPid (const uintptr_t sig)
{
	for(std::map<int, Bindable_t*>::iterator i=Pids.begin(); i != Pids.end(); i++)
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

const uintptr_t EventMachine_t::WatchFile (const char *fpath)
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

	wd = inotify_add_watch(inotify->GetSocket(), fpath,
			       IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF | IN_CREATE | IN_DELETE | IN_MOVE) ;
	if (wd == -1) {
		char errbuf[300];
		sprintf(errbuf, "failed to open file %s for registering with inotify: %s", fpath, strerror(errno));
		throw std::runtime_error(errbuf);
	}
	#endif

	#ifdef HAVE_KQUEUE
	if (Poller != Poller_Kqueue)
		throw std::runtime_error("must enable kqueue (EM.kqueue=true) for file watching support");

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
		Files.insert(std::make_pair (wd, b));

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

void EventMachine_t::UnwatchFile (const uintptr_t sig)
{
	for(std::map<int, Bindable_t*>::iterator i=Files.begin(); i != Files.end(); i++)
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
	char buffer[1024];

	assert(EventCallback);

	for (;;) {
		int returned = read(inotify->GetSocket(), buffer, sizeof(buffer));
		assert(!(returned == 0 || (returned == -1 && errno == EINVAL)));
		if (returned <= 0) {
			break;
		}
		int current = 0;
		while (current < returned) {
			struct inotify_event* event = (struct inotify_event*)(buffer+current);
			std::map<int, Bindable_t*>::const_iterator bindable = Files.find(event->wd);
			if (bindable != Files.end()) {
				if (event->mask & (IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVE)){
					(*EventCallback)(bindable->second->GetBinding(), EM_CONNECTION_READ, "modified", 8);
				}
				if (event->mask & IN_MOVE_SELF){
					(*EventCallback)(bindable->second->GetBinding(), EM_CONNECTION_READ, "moved", 5);
				}
				if (event->mask & IN_DELETE_SELF) {
					(*EventCallback)(bindable->second->GetBinding(), EM_CONNECTION_READ, "deleted", 7);
					UnwatchFile ((int)event->wd);
				}
			}
			current += sizeof(struct inotify_event) + event->len;
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
