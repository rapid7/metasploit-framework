#include "common.h"

#ifndef _WIN32
#include <pthread.h>

int __futex_wait(volatile void *ftx, int val, const struct timespec *timeout);
int __futex_wake(volatile void *ftx, int count);

#include <time.h>
#include <signal.h>

#endif

// thread.c contains wrappers for the primitives of locks, events and threads for use in 
// the multithreaded meterpreter. This is the win32/win64 implementation.

/*****************************************************************************************/

/*
 * Create a new lock. We choose Mutex's over CriticalSections as their appears to be an issue
 * when using CriticalSections with OpenSSL on some Windows systems. Mutex's are not as optimal
 * as CriticalSections but they appear to resolve the OpenSSL deadlock issue.
 */
LOCK * lock_create( VOID )
{
	LOCK * lock = (LOCK *)malloc( sizeof( LOCK ) );
	if( lock != NULL )
	{
		memset( lock, 0, sizeof( LOCK ) );

#ifdef _WIN32
		lock->handle = CreateMutex( NULL, FALSE, NULL );
#else
		pthread_mutex_init(lock->handle, NULL);
#endif
	}
	return lock;
}

/*
 * Destroy a lock that is no longer required.
 */
VOID lock_destroy( LOCK * lock )
{
	if( lock != NULL  )
	{
		lock_release( lock );

#ifdef _WIN32
		CloseHandle( lock->handle );
#else
		pthread_mutex_destroy(lock->handle);
#endif

		free( lock );
	}
}

/*
 * Acquire a lock and block untill it is acquired.
 */
VOID lock_acquire( LOCK * lock )
{
	if( lock != NULL  ) {
#ifdef _WIN32
		WaitForSingleObject( lock->handle, INFINITE );
#else
		pthread_mutex_lock(lock->handle);
#endif
	}
}

/*
 * Release a lock previously held.
 */
VOID lock_release( LOCK * lock )
{
	if( lock != NULL  ) {
#ifdef _WIN32
		ReleaseMutex( lock->handle );
#else
		pthread_mutex_unlock(lock->handle);
#endif
	}
}

/*****************************************************************************************/

/*
 * Create a new event which can be signaled/polled/and blocked on.
 */
EVENT * event_create( VOID )
{
	EVENT * event = NULL;

	event = (EVENT *)malloc( sizeof( EVENT ) );
	if( event == NULL )
		return NULL;

	memset( event, 0, sizeof( EVENT ) );

#ifdef _WIN32
	event->handle = CreateEvent( NULL, FALSE, FALSE, NULL );
	if( event->handle == NULL )
	{
		free( event );
		return NULL;
	}
#endif

	return event;
}

/*
 * Destroy an event.
 */
BOOL event_destroy( EVENT * event )
{
	if( event == NULL )
		return FALSE;

#ifdef _WIN32
	CloseHandle( event->handle );
#endif

	free( event );

	return TRUE;
}

/*
 * Signal an event.
 */
BOOL event_signal( EVENT * event )
{
	if( event == NULL )
		return FALSE;

#ifdef _WIN32
	if( SetEvent( event->handle ) == 0 )
		return FALSE;
#else 
	event->handle = (HANDLE)1;
	__futex_wake(&(event->handle), 1);
#endif

	return TRUE;
}

/*
 * Poll an event to see if it has been signaled. Set timeout to -1 to block indefinatly.
 * If timeout is 0 this function does not block but returns immediately.
 */
BOOL event_poll( EVENT * event, DWORD timeout )
{
	if( event == NULL )
		return FALSE;

#ifdef _WIN32
	if( WaitForSingleObject( event->handle, timeout ) == WAIT_OBJECT_0 )
		return TRUE;

	return FALSE;
#else
	// DWORD WINAPI WaitForSingleObject(
	// __in  HANDLE hHandle,
	// __in  DWORD dwMilliseconds
	// );
	// http://msdn.microsoft.com/en-us/library/ms687032(VS.85).aspx

	if(timeout) {
		struct timespec ts;

		// XXX, need to verify for -1. below modified from bionic/pthread.c
		// and maybe loop if needed ;\

		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout%1000)*1000000;
		if (ts.tv_nsec >= 1000000000) {
			ts.tv_sec++;
			ts.tv_nsec -= 1000000000;
		}

		// atomically checks if event->handle is 0, if so, 
		// it sleeps for timeout. if event->handle is 1, it 
		// returns straight away.

		__futex_wait(&(event->handle), 0, &ts);
	}

	return event->handle ? TRUE : FALSE;
#endif
}

/*****************************************************************************************/

/*
 * Opens and create a THREAD item for the current/calling thread.
 */
THREAD * thread_open( VOID )
{
	THREAD * thread        = NULL;
#ifdef _WIN32
	OPENTHREAD pOpenThread = NULL;
	HMODULE hKernel32      = NULL;


	thread = (THREAD *)malloc( sizeof( THREAD ) );
	if( thread != NULL )
	{
		memset( thread, 0, sizeof(THREAD) );
			
		thread->id      = GetCurrentThreadId();
		thread->sigterm = event_create();

		// Windows specific process of opening a handle to the current thread which
		// works on NT4 up. We only want THREAD_TERMINATE|THREAD_SUSPEND_RESUME access
		// for now.

		// First we try to use the normal OpenThread function, available on Windows 2000 and up...
		hKernel32 = LoadLibrary( "kernel32.dll" );
		pOpenThread = (OPENTHREAD)GetProcAddress( hKernel32, "OpenThread" );
		if( pOpenThread )
		{
			thread->handle = pOpenThread( THREAD_TERMINATE|THREAD_SUSPEND_RESUME, FALSE, thread->id );
		}
		else
		{
			NTOPENTHREAD pNtOpenThread = NULL;
			// If we can't use OpenThread, we try the older NtOpenThread function as found on NT4 machines.
			HMODULE hNtDll = LoadLibrary( "ntdll.dll" );
			pNtOpenThread = (NTOPENTHREAD)GetProcAddress( hNtDll, "NtOpenThread" );
			if( pNtOpenThread )
			{
				_OBJECT_ATTRIBUTES oa = {0};
				_CLIENT_ID cid        = {0};

				cid.UniqueThread = (PVOID)thread->id;

				pNtOpenThread( &thread->handle, THREAD_TERMINATE|THREAD_SUSPEND_RESUME, &oa, &cid );
			}

			FreeLibrary( hNtDll );
		}

		FreeLibrary( hKernel32 );
	}

	return thread;
#else
	thread = (THREAD *)malloc( sizeof( THREAD ) );

	if( thread != NULL )
	{
		memset( thread, 0, sizeof(THREAD) );

		thread->id      = gettid();
		thread->sigterm = event_create();
		thread->pid	= pthread_self();
	}
	return thread;
#endif
}

#ifndef _WIN32

struct thread_conditional {
	pthread_mutex_t suspend_mutex;
	pthread_cond_t suspend_cond;
	int engine_running;
	THREADFUNK (*funk)(void *arg);
	THREAD *thread;
};

void __thread_cancelled(int signo)
{
	signal(SIGTERM, SIG_DFL);
	pthread_exit(NULL);
}

/*
 * This is the entry point for threads created with thread_create. 
 * 
 * To implement suspended threads, we need to do some messing around with
 * mutexes and conditional broadcasts ;\
 */

void *__paused_thread(void *req)
{
	LPVOID (*funk)(void *arg);
	THREAD *thread;

	struct thread_conditional *tc = (struct thread_conditional *)(req);
	tc->thread->id = gettid();

	signal(SIGTERM, __thread_cancelled);

	pthread_mutex_lock(&tc->suspend_mutex);

	while(tc->engine_running == FALSE) {
		pthread_cond_wait(&tc->suspend_cond, &tc->suspend_mutex);
	}

	pthread_mutex_unlock(&tc->suspend_mutex);

	funk = tc->funk;
	thread = tc->thread;
	free(tc); 

	return funk(thread);	
}
#endif

/*
 * Create a new thread in a suspended state.
 */
THREAD * thread_create( THREADFUNK funk, LPVOID param1, LPVOID param2 )
{
	THREAD * thread = NULL;
	
	if( funk == NULL )
		return NULL;

	thread = (THREAD *)malloc( sizeof( THREAD ) );
	if( thread == NULL )
		return NULL;

	memset( thread, 0, sizeof( THREAD ) );

	thread->sigterm = event_create();
	if( thread->sigterm == NULL )
	{
		free( thread );
		return NULL;
	}


	thread->parameter1 = param1;
	thread->parameter2 = param2;

#ifdef _WIN32
	thread->handle = CreateThread( NULL, 0, funk, thread, CREATE_SUSPENDED, &thread->id );

	if( thread->handle == NULL )
	{
		event_destroy( thread->sigterm );
		free( thread );
		return NULL;
	}

#else
	// PKS, this is fucky.
	// we need to use conditionals to implement this. 

	do {
		pthread_t pid;

		struct thread_conditional *tc;
		tc = (struct thread_conditional *) malloc(sizeof(struct thread_conditional));

		if( tc == NULL ) {
			event_destroy(thread->sigterm);
			free(thread);
			return NULL;
		}
		
		memset( tc, 0, sizeof(struct thread_conditional));

		pthread_mutex_init(&tc->suspend_mutex, NULL);
		pthread_cond_init(&tc->suspend_cond, NULL);

		tc->funk = funk;		
		tc->thread = thread;

		thread->suspend_thread_data = (void *)(tc);

		if(pthread_create(&(thread->pid), NULL, __paused_thread, tc) == -1) {
			free(tc);
			event_destroy(thread->sigterm);
			free(thread);
			return NULL;
		}
		// __paused_thread free's the allocated memory.

	} while(0);
#endif

	return thread;
}

/*
 * Run a thread.
 */
BOOL thread_run( THREAD * thread )
{
	if( thread == NULL )
		return FALSE;

#ifdef _WIN32
	if( ResumeThread( thread->handle ) < 0 )
		return FALSE;

#else
	struct thread_conditional *tc;
	tc = (struct thread_conditional *)thread->suspend_thread_data;
	pthread_mutex_lock(&tc->suspend_mutex);
	tc->engine_running = TRUE;
	pthread_mutex_unlock(&tc->suspend_mutex);
	pthread_cond_signal(&tc->suspend_cond);
#endif
	return TRUE;
}

/*
 * Signals the thread to terminate. It is the responsibility of the thread to wait for and process this signal.
 * Should be used to signal the thread to terminate.
 */
BOOL thread_sigterm( THREAD * thread )
{
	if( thread == NULL )
		return FALSE;

	return event_signal( thread->sigterm );
}

/*
 * Terminate a thread. Use with caution! better to signal your thread to terminate and wait for it to do so.
 */
BOOL thread_kill( THREAD * thread )
{
	if( thread == NULL )
		return FALSE;

#ifdef _WIN32
	if( TerminateThread( thread->handle, -1 ) == 0 )
		return FALSE;

	return TRUE;
#else
	// bionic/libc/bionic/CAVEATS
	// - pthread cancellation is *not* supported. this seemingly simple "feature" is the source
	// of much bloat and complexity in a C library. Besides, you'd better write correct
	// multi-threaded code instead of relying on this stuff.

	// pthread_kill says: Note  that  pthread_kill()  only  causes  the
	// signal to be handled in the context of the given thread; the signal
	// action (termination or stopping) affects the process as a whole.

	// We send our thread a SIGTERM, and a signal handler calls pthread_exit().

	pthread_kill(thread->id, SIGTERM);
	return FALSE;
#endif
}


/*
 * Blocks untill the thread has terminated.
 */
BOOL thread_join( THREAD * thread )
{
	if( thread == NULL )
		return FALSE;

#ifdef _WIN32
	if( WaitForSingleObject( thread->handle, INFINITE ) == WAIT_OBJECT_0 )
		return TRUE;

	return FALSE;
#else
	if(pthread_join(thread->pid, NULL) == 0) 
		return TRUE;

	return FALSE;
#endif
}

/*
 * Destroys a previously created thread. Note, this does not terminate the thread. You must signal your
 * thread to terminate and wait for it to do so (via thread_signal/thread_join).
 */
BOOL thread_destroy( THREAD * thread )
{
	if( thread == NULL )
		return FALSE;
	
	event_destroy( thread->sigterm );

#ifdef _WIN32
	CloseHandle( thread->handle );
#else
	pthread_detach(thread->pid);
#endif

	free( thread );

	return TRUE;
}
