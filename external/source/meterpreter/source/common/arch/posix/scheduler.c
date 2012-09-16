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

int nentries = 0;
int ntableentries = 0;
struct pollfd *polltable;
LIST_HEAD(_WaitableEntryHead, _WaitableEntry) WEHead;

THREAD *scheduler_thread;

int stop_reaper = 0;

/*
 * If there are no waitables in the queue, we wait
 * for a conditional broadcast to start it.
 */

pthread_mutex_t scheduler_mutex;
pthread_cond_t scheduler_cond;

DWORD scheduler_run(THREAD *thread);
     
DWORD scheduler_destroy( VOID )
{
	WaitableEntry *current, *tmp;

	dprintf("Shutdown of scheduler requested");

	if(scheduler_thread)
	{
		dprintf("sigterm'ing thread");
		thread_sigterm(scheduler_thread);

		// wake up the thread if needed
		pthread_cond_signal(&scheduler_cond);

		// can delay execution up to 2 sec give or take
		thread_join(scheduler_thread);

		// free up memory
		thread_destroy(scheduler_thread);
		scheduler_thread = NULL;

		dprintf("stopping zombie reaper");
		stop_zombie_reaper();

		dprintf("thread joined .. going for polltable");

		if(polltable)
		{
			free(polltable);
			polltable = NULL;
			nentries = ntableentries = 0;
		}

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


/*
 * Reap child zombie threads on linux 2.4 (before NPTL)
 * each thread appears as a process and pthread_join don't necessarily reap it
 * threads are created using the clone syscall, so use special __WCLONE flag in waitpid
 */

VOID reap_zombie_thread(void * param)
{
	pid_t pid;
	BOOL success;
	pthread_internal_t * ptr = (pthread_internal_t *)reaper_tid; 
 //       dprintf("reap_zombie_thread : getpid : %d , getppid : %d, gettid : %d, kernel_id : %d, is_kernel_24 : %d", getpid(), getppid(), gettid(), ptr->kernel_id, is_kernel_24);
	// when tested, this means we are on a 2.4 kernel
	if (getpid() == getppid())
		is_kernel_24 = 1;
	else
		is_kernel_24 = 0;

	/*
	 * on a 2.4 kernel, we need the reaper
	 */
	if (is_kernel_24 == 1) {
		/* reap until asked to exit
		 * at this point, will reap any remaining zombie before exiting
		 */
		while( stop_reaper == 0 || (stop_reaper == 1 && list_count(commandThreadListPID) > 0)) {
			pid = waitpid(-1, NULL, __WCLONE);
			if (pid > 0) {
				success = list_remove(commandThreadListPID, pid);
//				dprintf("tried to remove pid : %d , success : %d",pid, success);
			}
	        }
	}
	pthread_exit(0);
}

/* 
 * ask the zombie reaper to stop
 * before stopping, the reaper will reap all remaining threads created, including the scheduler
 */

VOID stop_zombie_reaper( VOID )
{
	pid_t pid;
	pthread_internal_t * ptr;
	// 2.6/3.x kernel don't have zombie reaper
	if (is_kernel_24 == 0)
		return;
	// stop zombie reaper
        stop_reaper = 1;
	ptr = (pthread_internal_t *)reaper_tid;
	// reap reaper thread itself
	pid = waitpid(ptr->kernel_id, NULL, __WCLONE);
	dprintf("zombie_reaper kernel_id : %d, ret pid : %d (should be equal)",ptr->kernel_id, pid);
	// all zombies have been reaped, including scheduler one (it was inserted into commandThreadListPID)
	list_destroy(commandThreadListPID);
	commandThreadListPID = NULL;
	return;

}

DWORD scheduler_initialize( Remote * remote )
{
	if(scheduler_thread) {
		dprintf("Hmmm. scheduler_initialize() called twice?");
		return ERROR_SUCCESS;
	}

	pthread_mutex_init(&scheduler_mutex, NULL);
	pthread_cond_init(&scheduler_cond, NULL);

	// create zombie thread reaper for pre-NPTL (in 2.4 kernels) threads
	pthread_attr_t tattr;
	pthread_attr_init(&tattr);
	pthread_attr_setdetachstate(&tattr,PTHREAD_CREATE_DETACHED);
	pthread_create(&reaper_tid, &tattr, reap_zombie_thread, NULL);

	while (is_kernel_24 == -1) usleep(10000);
	// here, we know if we're on a 2.4 kernel or not
	

	scheduler_thread = thread_create(scheduler_run, remote, NULL);
	if(! scheduler_thread) {
		return ENOMEM;
	}

	thread_run(scheduler_thread);

	dprintf("Initialized scheduler thread and started it running");

	return ERROR_SUCCESS;
}

/*
 * Insert a waitable object for checking and processing
 */
DWORD
scheduler_insert_waitable(HANDLE waitable, LPVOID context,
    WaitableNotifyRoutine routine)
{
	DWORD retcode = ERROR_SUCCESS;

	WaitableEntry *current;
	struct pollfd *polltableprev;

	pthread_mutex_lock(&scheduler_mutex);

	//dprintf("Handle: %d, context: 0x%08x, routine: 0x%08x. nentries = %d, polltable = 0x%08x",
	//	waitable, context, routine, nentries, polltable);

	do {
		if ((current = malloc(sizeof(WaitableEntry))) == NULL) {
			retcode = ENOMEM;
			break;
		}

		nentries++;

		if (nentries > ntableentries) {
			polltableprev = polltable;

			// We do *2 because reallocating every scheduler_insert_waitable
			// is slower than need be.

			polltable = malloc((nentries*2)*sizeof(struct pollfd));

			if (polltable == NULL) {
				nentries--;
				polltable = polltableprev;
				free(current);

				retcode = ENOMEM;
				break;
			}

			if (polltableprev != NULL)
				free(polltableprev);

			ntableentries = (nentries*2);
		}
		current->waitable = waitable;
		current->context = context;
		current->routine = routine;

		LIST_INSERT_HEAD(&WEHead, current, link);


	} while(0);


	dprintf("WEHead: %08x, Now nentries = %d, and polltable = 0x%08x. LIST_EMPTY: %d", &WEHead, nentries, polltable, LIST_EMPTY(&WEHead));
	/*
	LIST_FOREACH(current, &WEHead, link)
		dprintf("current->waitable: %d, current->context: %08x, current->routine: %08x",
			current->waitable, current->context, current->routine);
	*/

	pthread_mutex_unlock(&scheduler_mutex);

	// wake up scheduler if needed.
	pthread_cond_signal(&scheduler_cond);

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

		LIST_REMOVE(current, link);
		free(current);
		nentries--;
	} while(0);

	pthread_mutex_unlock(&scheduler_mutex);

	return retcode;
}

/*
 * Runs the scheduler, checking waitable objects for data
 */
DWORD
scheduler_run(THREAD *thread)
{
	Remote *remote;
	remote = (Remote *) thread->parameter1;
	WaitableEntry *current, *tmp;
	int ret, i, found, idx;
	int timeout;

	timeout = 1000;

	// see if we can modify this code to use waitable as the index into polltable
	// and waitable events. saves time looking up in exchange for more memory use.

	pthread_mutex_lock(&scheduler_mutex);

	dprintf("Beginning loop");

	while( event_poll(thread->sigterm, 0) == FALSE )
	{
		// scheduler_mutex is held upon entry and execution of the loop

		idx = 0;

		while(event_poll(thread->sigterm, 0) == FALSE && (LIST_EMPTY(&WEHead) || polltable == NULL)) {
			// XXX I'd prefer to use pthread_cond_timedwait, but it's broken in bionic and just
			// chews cpu

			//dprintf(" Waiting for conditional (%08x). %d vs %d",
			//	&scheduler_cond, LIST_EMPTY(&WEHead), polltable == NULL);

			pthread_cond_wait(&scheduler_cond, &scheduler_mutex);

			// pthread_cond_wait still chews CPU in some cases, usleep to yield
			// processor so we don't just spin.
			usleep(1000);
		}

		LIST_FOREACH(current, &WEHead, link) {
			dprintf("current->waitable: %d, current->context: %08x, current->routine: %08x",
				current->waitable, current->context, current->routine);
			polltable[idx].fd = current->waitable;
			polltable[idx].events = POLLRDNORM;
			polltable[idx].revents = 0;
			idx++;
		}

		dprintf("Created a polltable of %d", idx);

		pthread_mutex_unlock(&scheduler_mutex);

		ret = poll(polltable, idx, timeout);

		pthread_mutex_lock(&scheduler_mutex);

		if(ret == 0) continue;
		if(ret == -1) {
			if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				continue;
			}
			dprintf("poll() failed, errno: %d (%s). Sleeping 1 second and retrying", errno, strerror(errno));
			sleep(1);
			continue;
		}

		for (found = i = 0; i < idx && found < ret; i++)
		{
			if (polltable[i].revents)
			{
				LIST_FOREACH(current, &WEHead, link)
				    if (current->waitable == polltable[i].fd)
					    break;

				if(current)
				{
					ret = current->routine(remote, current->context);
					if(ret != ERROR_SUCCESS)
					{
						// could call close due to remote, but it would deadlock
						// if it calls remove waitable
						// could make a separate list to handle when we are not locking
						// unlink and let rest deal with it ?

						dprintf("current->routine (%08x / %08x) returned an error message. destroying", current->routine, current->context);

						LIST_REMOVE(current, link);
						close(current->waitable);
						channel_close((Channel *)current->context, remote, NULL, 0, NULL);
						free(current);

						nentries--;

					}
				}
			}
		}
	}

	dprintf("Ending loop");

	pthread_mutex_unlock(&scheduler_mutex);
}


