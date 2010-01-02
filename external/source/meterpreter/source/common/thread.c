#include "common.h"

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

		lock->handle = CreateMutex( NULL, FALSE, NULL );
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

		CloseHandle( lock->handle );

		free( lock );
	}
}

/*
 * Acquire a lock and block untill it is acquired.
 */
VOID lock_acquire( LOCK * lock )
{
	if( lock != NULL  )
		WaitForSingleObject( lock->handle, INFINITE );
}

/*
 * Release a lock previously held.
 */
VOID lock_release( LOCK * lock )
{
	if( lock != NULL  )
		ReleaseMutex( lock->handle );
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

	event->handle = CreateEvent( NULL, FALSE, FALSE, NULL );
	if( event->handle == NULL )
	{
		free( event );
		return NULL;
	}

	return event;
}

/*
 * Destroy an event.
 */
BOOL event_destroy( EVENT * event )
{
	if( event == NULL )
		return FALSE;

	CloseHandle( event->handle );

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

	if( SetEvent( event->handle ) == 0 )
		return FALSE;

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

	if( WaitForSingleObject( event->handle, timeout ) == WAIT_OBJECT_0 )
		return TRUE;

	return FALSE;
}

/*****************************************************************************************/

/*
 * Opens and create a THREAD item for the current/calling thread.
 */
THREAD * thread_open( VOID )
{
	OPENTHREAD pOpenThread = NULL;
	HMODULE hKernel32      = NULL;
	THREAD * thread        = NULL;

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
}

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

	thread->handle = CreateThread( NULL, 0, funk, thread, CREATE_SUSPENDED, &thread->id );
	if( thread->handle == NULL )
	{
		event_destroy( thread->sigterm );
		free( thread );
		return NULL;
	}

	return thread;
}

/*
 * Run a thread.
 */
BOOL thread_run( THREAD * thread )
{
	if( thread == NULL )
		return FALSE;

	if( ResumeThread( thread->handle ) < 0 )
		return FALSE;

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

	if( TerminateThread( thread->handle, -1 ) == 0 )
		return FALSE;

	return TRUE;
}


/*
 * Blocks untill the thread has terminated.
 */
BOOL thread_join( THREAD * thread )
{
	if( thread == NULL )
		return FALSE;

	if( WaitForSingleObject( thread->handle, INFINITE ) == WAIT_OBJECT_0 )
		return TRUE;

	return FALSE;
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

	CloseHandle( thread->handle );

	free( thread );

	return TRUE;
}
