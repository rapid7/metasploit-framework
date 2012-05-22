#include "queue.h"
#include "common.h"
#include <poll.h>

#include <pthread.h>

typedef struct _WaitableEntry
{
	HANDLE                waitable;
	LPVOID                context;
	WaitableNotifyRoutine routine;
	LIST_ENTRY(_WaitableEntry) link;
} WaitableEntry;

LIST_HEAD(_WaitableEntryHead, _WaitableEntry) WEHead;

THREAD *scheduler_thread = NULL;
Remote *scheduler_remote = NULL;

/*
 * If there are no waitables in the queue, we wait
 * for a conditional broadcast to start it.
 */

pthread_mutex_t scheduler_mutex;
pthread_cond_t scheduler_cond;

DWORD scheduler_destroy( VOID )
{
	WaitableEntry *current, *tmp;

	dprintf("Shutdown of scheduler requested");

	if(scheduler_thread)
	{
		dprintf("sigterm'ing thread");
		thread_sigterm(scheduler_thread);

		// can delay execution up to 2 sec give or take
		thread_join(scheduler_thread);

		// free up memory
		thread_destroy(scheduler_thread);
		scheduler_thread = NULL;

		dprintf("Now for the fun part, iterating through list and removing items");

		LIST_FOREACH_SAFE(current, &WEHead, link, tmp)
		{
			// can't call close function due to no remote struct
			// will segfault if we try
			// XXX could steal from scheduler_thread->parameter1 ?

			dprintf("current: %08x, current->routine: %08x", current, current->routine);

			LIST_REMOVE(current, link);
			close(current->waitable);
			free(current->context);
			free(current);
		}

		dprintf("All done. Leaving");

	}
	return ERROR_SUCCESS;
}

DWORD scheduler_initialize( Remote * remote )
{
	if(scheduler_thread) {
		dprintf("Hmmm. scheduler_initialize() called twice?");
		return ERROR_SUCCESS;
	}
	scheduler_remote = remote;

	pthread_mutex_init(&scheduler_mutex, NULL);
	pthread_cond_init(&scheduler_cond, NULL);

	return ERROR_SUCCESS;
}

/*
 * Insert a waitable object for checking and processing
 */
DWORD
scheduler_insert_waitable(HANDLE waitable, LPVOID context, WaitableNotifyRoutine routine)
{
	DWORD retcode = ERROR_SUCCESS;
	THREAD *th;

	WaitableEntry *current;

	dprintf("inserting Handle: %d, context: 0x%08x, routine: 0x%08x.", waitable, context, routine);

	do {
		if ((current = malloc(sizeof(WaitableEntry))) == NULL) {
			retcode = ENOMEM;
			break;
		}
		dprintf("Malloc'd new entry: %08x", current);

		current->waitable = waitable;
		current->context = context;
		current->routine = routine;

		dprintf("Acquiring lock to insert Handle: %d", waitable);
		pthread_mutex_lock(&scheduler_mutex);
		dprintf("Acquired lock inserting Handle: %d", waitable);

		LIST_INSERT_HEAD(&WEHead, current, link);

		dprintf("Unlocking mutex");
		pthread_mutex_unlock(&scheduler_mutex);

		dprintf("Creating thread with current: %08x", current);
		th = thread_create(scheduler_waitable_thread, (LPVOID)current, NULL);
		dprintf("Running thread");
		thread_run(th);
		dprintf("Ran thread");

	} while(0);


	return retcode;
}

/*
 * Remove a waitable object
 */
DWORD
scheduler_remove_waitable(HANDLE waitable)
{
	DWORD retcode = ERROR_SUCCESS;
	WaitableEntry *current;

	dprintf("Handle: %d", waitable);

	pthread_mutex_lock(&scheduler_mutex);

	do {
		LIST_FOREACH(current, &WEHead, link)
		    if (current->waitable == waitable)
			    break;

		if (current == NULL) {
			retcode = ENOENT;
			break;
		}

		dprintf("Removing waitable");
		LIST_REMOVE(current, link);
		free(current);
	} while(0);

	pthread_mutex_unlock(&scheduler_mutex);

	return retcode;
}


DWORD THREADCALL
scheduler_waitable_thread( THREAD * thread )
{
	WaitableEntry * current = NULL;
	int ret;

	dprintf("Grabbing entry from thread (%08x) params", thread);
	current = (WaitableEntry *)thread->parameter1;

	dprintf("Calling routine for waitable %d, remote: %08x, ctx: %08x",
			current->waitable, scheduler_remote, current->context);
	// This is where the magic happens
	ret = current->routine(scheduler_remote, current->context);

	if (ret != ERROR_SUCCESS) {
		dprintf("Routine for waitable %d returned failure, cleaning up", current->waitable);

		// Now clean up
		channel_close((Channel *)current->context, scheduler_remote, NULL, 0, NULL);
		scheduler_remove_waitable(current->waitable);
	}

	return ERROR_SUCCESS;
}


