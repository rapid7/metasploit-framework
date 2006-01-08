//				Package : omnithread
// omnithread.h			Created : 7/94 tjr
//
//    Copyright (C) 1994,1995,1996, 1997 Olivetti & Oracle Research Laboratory
//
//    This file is part of the omnithread library
//
//    The omnithread library is free software; you can redistribute it and/or
//    modify it under the terms of the GNU Library General Public
//    License as published by the Free Software Foundation; either
//    version 2 of the License, or (at your option) any later version.
//
//    This library is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//    Library General Public License for more details.
//
//    You should have received a copy of the GNU Library General Public
//    License along with this library; if not, write to the Free
//    Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  
//    02111-1307, USA
//

//
// Interface to OMNI thread abstraction.
//
// This file declares classes for threads and synchronisation objects
// (mutexes, condition variables and counting semaphores).
//
// Wherever a seemingly arbitrary choice has had to be made as to the interface
// provided, the intention here has been to be as POSIX-like as possible.  This
// is why there is no semaphore timed wait, for example.
//

#ifndef __omnithread_h_
#define __omnithread_h_

#ifndef NULL
#define NULL (void*)0
#endif

class omni_mutex;
class omni_condition;
class omni_semaphore;
class omni_thread;

//
// OMNI_THREAD_EXPOSE can be defined as public or protected to expose the
// implementation class - this may be useful for debugging.  Hopefully this
// won't change the underlying structure which the compiler generates so that
// this can work without recompiling the library.
//

#ifndef OMNI_THREAD_EXPOSE
#define OMNI_THREAD_EXPOSE private
#endif

//
// Include implementation-specific header file.
//
// This must define 4 CPP macros of the form OMNI_x_IMPLEMENTATION for mutex,
// condition variable, semaphore and thread.  Each should define any
// implementation-specific members of the corresponding classes.
//


#if defined(__arm__) && defined(__atmos__)
#include <omnithread/posix.h>

#elif defined(__alpha__) && defined(__osf1__)
#include <omnithread/posix.h>

#elif defined(__powerpc__) && defined(__aix__)
#include <omnithread/posix.h>

#elif defined(__hpux__)
#include <omnithread/posix.h>

#elif defined(__WIN32__)

#if defined(__POSIX_NT__)
#include <omnithread/posix.h>
#else
#include <omnithread/nt.h>
#endif

#ifdef _MSC_VER

// Using MSVC++ to compile. If compiling library as a DLL,
// define _OMNITHREAD_DLL. If compiling as a statuc library, define
// _WINSTATIC
// If compiling an application that is to be statically linked to omnithread,
// define _WINSTATIC (if the application is  to be dynamically linked, 
// there is no need to define any of these macros).

#if defined (_OMNITHREAD_DLL) && defined(_WINSTATIC)
#error "Both _OMNITHREAD_DLL and _WINSTATIC are defined."
#elif defined(_OMNITHREAD_DLL)
#define _OMNITHREAD_NTDLL_ __declspec(dllexport)
#elif !defined(_WINSTATIC)
#define _OMNITHREAD_NTDLL_ __declspec(dllimport)
#elif defined(_WINSTATIC)
#define _OMNITHREAD_NTDLL_
#endif
 // _OMNITHREAD_DLL && _WINSTATIC

#else

// Not using MSVC++ to compile
#define _OMNITHREAD_NTDLL_

#endif
 // _MSC_VER
 
#elif defined(__sunos__)
#if __OSVERSION__ != 5
// XXX Workaround for SUN C++ compiler (seen on 4.2) Template.DB code
//     regeneration bug. See omniORB2/CORBA_sysdep.h for details.
#if !defined(__SUNPRO_CC) || __OSVERSION__ != '5'
#error "Only SunOS 5.x or later is supported."
#endif
#endif
#ifdef UsePthread
#include <omnithread/posix.h>
#else
#include <omnithread/solaris.h>
#endif

#elif defined(__linux__)
#include <omnithread/posix.h>

#elif defined(__nextstep__)
#include <omnithread/mach.h>

#elif defined(__VMS)
#include <omnithread/posix.h>

#elif defined(__SINIX__)
#include <omnithread/posix.h>

#elif defined(__osr5__)
#include <omnithread/posix.h>

#elif defined(__uw7__)
#include <omnithread/posix.h>

#elif defined(__irix__)
#include <omnithread/posix.h>

#elif defined(__freebsd__)
#include <omnithread/posix.h>

#elif defined(__rtems__)
#include <omnithread/posix.h>
#include <sched.h>

#else
#error "No implementation header file"
#endif

#if !defined(__WIN32__)
#define _OMNITHREAD_NTDLL_
#endif

#if (!defined(OMNI_MUTEX_IMPLEMENTATION) || \
     !defined(OMNI_CONDITION_IMPLEMENTATION) || \
     !defined(OMNI_SEMAPHORE_IMPLEMENTATION) || \
     !defined(OMNI_THREAD_IMPLEMENTATION))
#error "Implementation header file incomplete"
#endif


//
// This exception is thrown in the event of a fatal error.
//

class _OMNITHREAD_NTDLL_ omni_thread_fatal {
public:
    int error;
    omni_thread_fatal(int e = 0) : error(e) {}
};


//
// This exception is thrown when an operation is invoked with invalid
// arguments.
//

class _OMNITHREAD_NTDLL_ omni_thread_invalid {};


///////////////////////////////////////////////////////////////////////////
//
// Mutex
//
///////////////////////////////////////////////////////////////////////////

class _OMNITHREAD_NTDLL_ omni_mutex {

public:
    omni_mutex(void);
    ~omni_mutex(void);

    void lock(void);
    void unlock(void);
    void acquire(void) { lock(); }
    void release(void) { unlock(); }
	// the names lock and unlock are preferred over acquire and release
	// since we are attempting to be as POSIX-like as possible.

    friend class omni_condition;

private:
    // dummy copy constructor and operator= to prevent copying
    omni_mutex(const omni_mutex&);
    omni_mutex& operator=(const omni_mutex&);

OMNI_THREAD_EXPOSE:
    OMNI_MUTEX_IMPLEMENTATION
};

//
// As an alternative to:
// {
//   mutex.lock();
//   .....
//   mutex.unlock();
// }
//
// you can use a single instance of the omni_mutex_lock class:
//
// {
//   omni_mutex_lock l(mutex);
//   ....
// }
//
// This has the advantage that mutex.unlock() will be called automatically
// when an exception is thrown.
//

class _OMNITHREAD_NTDLL_ omni_mutex_lock {
    omni_mutex& mutex;
public:
    omni_mutex_lock(omni_mutex& m) : mutex(m) { mutex.lock(); }
    ~omni_mutex_lock(void) { mutex.unlock(); }
private:
    // dummy copy constructor and operator= to prevent copying
    omni_mutex_lock(const omni_mutex_lock&);
    omni_mutex_lock& operator=(const omni_mutex_lock&);
};


///////////////////////////////////////////////////////////////////////////
//
// Condition variable
//
///////////////////////////////////////////////////////////////////////////

class _OMNITHREAD_NTDLL_ omni_condition {

    omni_mutex* mutex;

public:
    omni_condition(omni_mutex* m);
	// constructor must be given a pointer to an existing mutex. The
	// condition variable is then linked to the mutex, so that there is an
	// implicit unlock and lock around wait() and timed_wait().

    ~omni_condition(void);

    void wait(void);
	// wait for the condition variable to be signalled.  The mutex is
	// implicitly released before waiting and locked again after waking up.
	// If wait() is called by multiple threads, a signal may wake up more
	// than one thread.  See POSIX threads documentation for details.

    int timedwait(unsigned long secs, unsigned long nanosecs = 0);
	// timedwait() is given an absolute time to wait until.  To wait for a
	// relative time from now, use omni_thread::get_time. See POSIX threads
	// documentation for why absolute times are better than relative.
	// Returns 1 (true) if successfully signalled, 0 (false) if time
	// expired.

    void signal(void);
	// if one or more threads have called wait(), signal wakes up at least
	// one of them, possibly more.  See POSIX threads documentation for
	// details.

    void broadcast(void);
	// broadcast is like signal but wakes all threads which have called
	// wait().

private:
    // dummy copy constructor and operator= to prevent copying
    omni_condition(const omni_condition&);
    omni_condition& operator=(const omni_condition&);

OMNI_THREAD_EXPOSE:
    OMNI_CONDITION_IMPLEMENTATION
};


///////////////////////////////////////////////////////////////////////////
//
// Counting semaphore
//
///////////////////////////////////////////////////////////////////////////

class _OMNITHREAD_NTDLL_ omni_semaphore {

public:
    omni_semaphore(unsigned int initial = 1);
    ~omni_semaphore(void);

    void wait(void);
	// if semaphore value is > 0 then decrement it and carry on. If it's
	// already 0 then block.

    int trywait(void);
	// if semaphore value is > 0 then decrement it and return 1 (true).
	// If it's already 0 then return 0 (false).

    void post(void);
	// if any threads are blocked in wait(), wake one of them up. Otherwise
	// increment the value of the semaphore.

private:
    // dummy copy constructor and operator= to prevent copying
    omni_semaphore(const omni_semaphore&);
    omni_semaphore& operator=(const omni_semaphore&);

OMNI_THREAD_EXPOSE:
    OMNI_SEMAPHORE_IMPLEMENTATION
};

//
// A helper class for semaphores, similar to omni_mutex_lock above.
//

class _OMNITHREAD_NTDLL_ omni_semaphore_lock {
    omni_semaphore& sem;
public:
    omni_semaphore_lock(omni_semaphore& s) : sem(s) { sem.wait(); }
    ~omni_semaphore_lock(void) { sem.post(); }
private:
    // dummy copy constructor and operator= to prevent copying
    omni_semaphore_lock(const omni_semaphore_lock&);
    omni_semaphore_lock& operator=(const omni_semaphore_lock&);
};


///////////////////////////////////////////////////////////////////////////
//
// Thread
//
///////////////////////////////////////////////////////////////////////////

class _OMNITHREAD_NTDLL_ omni_thread {

public:

    enum priority_t {
	PRIORITY_LOW,
	PRIORITY_NORMAL,
	PRIORITY_HIGH
    };

    enum state_t {
	STATE_NEW,		// thread object exists but thread hasn't
				// started yet.
	STATE_RUNNING,		// thread is running.
	STATE_TERMINATED	// thread has terminated but storage has not
				// been reclaimed (i.e. waiting to be joined).
    };

    //
    // Constructors set up the thread object but the thread won't start until
    // start() is called. The create method can be used to construct and start
    // a thread in a single call.
    //

    omni_thread(void (*fn)(void*), void* arg = NULL,
		priority_t pri = PRIORITY_NORMAL);
    omni_thread(void* (*fn)(void*), void* arg = NULL,
		priority_t pri = PRIORITY_NORMAL);
	// these constructors create a thread which will run the given function
	// when start() is called.  The thread will be detached if given a
	// function with void return type, undetached if given a function
	// returning void*. If a thread is detached, storage for the thread is
	// reclaimed automatically on termination. Only an undetached thread
	// can be joined.

    void start(void);
	// start() causes a thread created with one of the constructors to
	// start executing the appropriate function.

protected:

    omni_thread(void* arg = NULL, priority_t pri = PRIORITY_NORMAL);
	// this constructor is used in a derived class.  The thread will
	// execute the run() or run_undetached() member functions depending on
	// whether start() or start_undetached() is called respectively.

    void start_undetached(void);
	// can be used with the above constructor in a derived class to cause
	// the thread to be undetached.  In this case the thread executes the
	// run_undetached member function.

    virtual ~omni_thread(void);
	// destructor cannot be called by user (except via a derived class).
	// Use exit() or cancel() instead. This also means a thread object must
	// be allocated with new - it cannot be statically or automatically
	// allocated. The destructor of a class that inherits from omni_thread
	// shouldn't be public either (otherwise the thread object can be
	// destroyed while the underlying thread is still running).

public:

    void join(void**);
	// join causes the calling thread to wait for another's completion,
	// putting the return value in the variable of type void* whose address
	// is given (unless passed a null pointer). Only undetached threads
	// may be joined. Storage for the thread will be reclaimed.

    void set_priority(priority_t);
	// set the priority of the thread.

    static omni_thread* create(void (*fn)(void*), void* arg = NULL,
			       priority_t pri = PRIORITY_NORMAL);
    static omni_thread* create(void* (*fn)(void*), void* arg = NULL,
			       priority_t pri = PRIORITY_NORMAL);
	// create spawns a new thread executing the given function with the
	// given argument at the given priority. Returns a pointer to the
	// thread object. It simply constructs a new thread object then calls
	// start.

    static void exit(void* return_value = NULL);
	// causes the calling thread to terminate.

    static omni_thread* self(void);
	// returns the calling thread's omni_thread object.
	// If the calling thread is not the main thread and
	// is not created using this library, returns 0.

    static void yield(void);
	// allows another thread to run.

    static void sleep(unsigned long secs, unsigned long nanosecs = 0);
	// sleeps for the given time.

    static void get_time(unsigned long* abs_sec, unsigned long* abs_nsec,
			 unsigned long rel_sec = 0, unsigned long rel_nsec=0);
	// calculates an absolute time in seconds and nanoseconds, suitable for
	// use in timed_waits on condition variables, which is the current time
	// plus the given relative offset.


    static void stacksize(unsigned long sz);
    static unsigned long stacksize();
        // Use this value as the stack size when spawning a new thread.
        // The default value (0) means that the thread library default is
        // to be used.

private:

    virtual void run(void* arg) {}
    virtual void* run_undetached(void* arg) { return NULL; }
	// can be overridden in a derived class.  When constructed using the
	// the constructor omni_thread(void*, priority_t), these functions are
	// called by start() and start_undetached() respectively.

    void common_constructor(void* arg, priority_t pri, int det);
	// implements the common parts of the constructors.

    omni_mutex mutex;
	// used to protect any members which can change after construction,
	// i.e. the following 2 members:

    state_t _state;
    priority_t _priority;

    static omni_mutex* next_id_mutex;
    static int next_id;
    int _id;

    void (*fn_void)(void*);
    void* (*fn_ret)(void*);
    void* thread_arg;
    int detached;

public:

    priority_t priority(void) {

	// return this thread's priority.

	omni_mutex_lock l(mutex);
	return _priority;
    }

    state_t state(void) {

	// return thread state (invalid, new, running or terminated).

	omni_mutex_lock l(mutex);
	return _state;
    }

    int id(void) { return _id; }
	// return unique thread id within the current process.


    // This class plus the instance of it declared below allows us to execute
    // some initialisation code before main() is called.

    class _OMNITHREAD_NTDLL_ init_t {
	static int count;
    public:
	init_t(void);
    };

    friend class init_t;

OMNI_THREAD_EXPOSE:
    OMNI_THREAD_IMPLEMENTATION
};

#ifndef __rtems__
static omni_thread::init_t omni_thread_init;
#else
// RTEMS calls global Ctor/Dtor in a context that is not
// a posix thread. Calls to functions to pthread_self() in
// that context returns NULL. 
// So, for RTEMS we will make the thread initialization at the
// beginning of the Init task that has a posix context.
#endif

#endif
