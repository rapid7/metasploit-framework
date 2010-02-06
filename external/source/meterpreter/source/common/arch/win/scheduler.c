#include "common.h"

typedef struct _WaitableEntry
{
	Remote *              remote;
	HANDLE                waitable;
	LPVOID                context;
	WaitableNotifyRoutine routine;
} WaitableEntry;

/*
 * The list of all currenltly running threads in the scheduler subsystem.
 */
LIST * schedulerThreadList = NULL;

/*
 * The Remote that is associated with the scheduler subsystem
 */
Remote * schedulerRemote   = NULL;

/*
 * Initialize the scheduler subsystem. Must be called before any calls to scheduler_insert_waitable.
 */
DWORD scheduler_initialize( Remote * remote )
{
	DWORD result = ERROR_SUCCESS;

	dprintf( "[SCHEDULER] entering scheduler_initialize." );

	if( remote == NULL )
		return ERROR_INVALID_HANDLE;

	schedulerThreadList = list_create();
	if( schedulerThreadList == NULL )
		return ERROR_INVALID_HANDLE;

	schedulerRemote = remote;

	dprintf( "[SCHEDULER] leaving scheduler_initialize." );

	return result;
}

/*
 * Destroy the scheduler subsystem. All waitable threads at signaled to terminate.
 * this function blocks untill all waitable threads have terminated.
 */
DWORD scheduler_destroy( VOID )
{
	DWORD result    = ERROR_SUCCESS;
	DWORD index     = 0;
	DWORD count     = 0;
	LIST * jlist    = list_create();
	THREAD * thread = NULL;

	dprintf( "[SCHEDULER] entering scheduler_destroy." );

	lock_acquire( schedulerThreadList->lock );

	count = list_count( schedulerThreadList );

	for( index=0 ; index < count ; index++ )
	{
		thread = (THREAD *)list_get( schedulerThreadList, index );
		if( thread == NULL )
			continue;
		
		list_push( jlist, thread );

		thread_sigterm( thread );
	}

	lock_release( schedulerThreadList->lock );

	dprintf( "[SCHEDULER] scheduler_destroy, joining all waitable threads..." );

	while( TRUE )
	{
		dprintf( "[SCHEDULER] scheduler_destroy, popping off another item from thread liat..." );
		
		thread = (THREAD *)list_pop( jlist );
		if( thread == NULL )
			break;

		dprintf( "[SCHEDULER] scheduler_destroy, joining thread 0x%08X...", thread );

		thread_join( thread );
	}

	dprintf( "[SCHEDULER] scheduler_destroy, destroying lists..." );

	list_destroy( jlist );
	
	list_destroy( schedulerThreadList );

	schedulerThreadList = NULL;

	dprintf( "[SCHEDULER] leaving scheduler_destroy." );

	return result;
}

/*
 * Insert a new waitable thread for checking and processing.
 */
DWORD scheduler_insert_waitable( HANDLE waitable, LPVOID context, WaitableNotifyRoutine routine )
{
	DWORD result = ERROR_SUCCESS;
	THREAD * swt = NULL;

	WaitableEntry * entry = (WaitableEntry *)malloc( sizeof( WaitableEntry ) );
	if( entry == NULL )
		return ERROR_NOT_ENOUGH_MEMORY;

	dprintf( "[SCHEDULER] entering scheduler_insert_waitable( 0x%08X, 0x%08X, 0x%08X )", waitable, context, routine );

	memset( entry, 0, sizeof( WaitableEntry ) );
	
	entry->remote   = schedulerRemote;
	entry->waitable = waitable;
	entry->context  = context;
	entry->routine  = routine;

	swt = thread_create( scheduler_waitable_thread, entry, NULL );
	if( swt != NULL )
	{
		dprintf( "[SCHEDULER] created scheduler_waitable_thread 0x%08X", swt );
		thread_run( swt );
	}
	else
	{
		free( entry );
		result = ERROR_INVALID_HANDLE;
	}

	dprintf( "[SCHEDULER] leaving scheduler_insert_waitable" );

	return result;
}

/*
 * Remove a waitable object by signaling the waitable thread to terminate.
 */
DWORD scheduler_remove_waitable( HANDLE waitable )
{
	DWORD index           = 0;
	DWORD count           = 0;
	THREAD * thread       = NULL;
	WaitableEntry * entry = NULL;
	DWORD result          = ERROR_SUCCESS;

	dprintf( "[SCHEDULER] entering scheduler_remove_waitable( 0x%08X )", waitable );

	if( schedulerThreadList == NULL || waitable == NULL )
		return ERROR_INVALID_HANDLE;

	lock_acquire( schedulerThreadList->lock );

	count = list_count( schedulerThreadList );

	for( index=0 ; index < count ; index++ )
	{
		thread = (THREAD *)list_get( schedulerThreadList, index );
		if( thread == NULL )
			continue;
	
		entry = (WaitableEntry *)thread->parameter1;
		if( entry == NULL )
			continue;

		if( entry->waitable == waitable )
		{
			dprintf( "[SCHEDULER] scheduler_remove_waitable: signaling waitable = 0x%08X, thread = 0x%08X", waitable, thread );
			thread_sigterm( thread );
			result = ERROR_SUCCESS;
			break;
		}
	}

	lock_release( schedulerThreadList->lock );

	dprintf( "[SCHEDULER] leaving scheduler_remove_waitable" );

	return result;
}

/*
 * The schedulers waitable thread. Each scheduled item will have its own thread which 
 * waits for either data to process or the threads signal to terminate.
 */
DWORD THREADCALL scheduler_waitable_thread( THREAD * thread )
{
	HANDLE waitableHandles[2] = {0};
	WaitableEntry * entry     = NULL;
	DWORD result              = 0;
	BOOL terminate            = FALSE;

	if( thread == NULL )
		return ERROR_INVALID_HANDLE;

	entry = (WaitableEntry *)thread->parameter1;
	if( entry == NULL )
		return ERROR_INVALID_HANDLE;

	if( entry->routine == NULL )
		return ERROR_INVALID_HANDLE;

	if( schedulerThreadList == NULL )
		return ERROR_INVALID_HANDLE;

	list_add( schedulerThreadList, thread );

	waitableHandles[0] = thread->sigterm->handle;
	waitableHandles[1] = entry->waitable;

	dprintf( "[SCHEDULER] entering scheduler_waitable_thread( 0x%08X )", thread );

	while( !terminate )
	{
		
		result = WaitForMultipleObjects( 2, (HANDLE *)&waitableHandles, FALSE, INFINITE );
		switch( result - WAIT_OBJECT_0 )
		{
			case 0:
				dprintf( "[SCHEDULER] scheduler_waitable_thread( 0x%08X ), signaled to terminate...", thread );
				terminate = TRUE;
				break;
			case 1:
				//dprintf( "[SCHEDULER] scheduler_waitable_thread( 0x%08X ), signaled on waitable...", thread );
				entry->routine( entry->remote, entry->context );
				break;
			default:
				break;
		}
	}

	dprintf( "[SCHEDULER] leaving scheduler_waitable_thread( 0x%08X )", thread );
	
	// we acquire the lock for this block as we are freeing 'entry' which may be accessed 
	// in a second call to scheduler_remove_waitable for this thread (unlikely but best practice).
	lock_acquire( schedulerThreadList->lock );
	if( list_remove( schedulerThreadList, thread ) )
	{
		if(entry->waitable) {
			dprintf( "[SCHEDULER] scheduler_waitable_thread( 0x%08X ) closing handle 0x%08X", thread, entry->waitable);
			CloseHandle( entry->waitable );
		}
		thread_destroy( thread );
		free( entry );
	}
	lock_release( schedulerThreadList->lock );

	return ERROR_SUCCESS;
}