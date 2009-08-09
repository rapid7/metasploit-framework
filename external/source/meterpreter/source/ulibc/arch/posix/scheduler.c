#include "queue.h"
#include "common.h"
#include <poll.h>

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
					      
/*
 * Insert a waitable object for checking and processing
 */
DWORD
scheduler_insert_waitable(HANDLE waitable, LPVOID context,
    WaitableNotifyRoutine routine)
{
	WaitableEntry *current;
	struct pollfd *polltableprev;
	
	if ((current = malloc(sizeof(WaitableEntry))) == NULL)
		return (ENOMEM);
	nentries++;
	if (nentries > ntableentries) {
		polltableprev = polltable;
		polltable = malloc(nentries*sizeof(struct pollfd));
		if (polltable == NULL) {
			polltable = polltableprev;
			free(current);
			return (ENOMEM);
		} else if (polltableprev != NULL)
			free(polltableprev);		
		ntableentries = nentries;
	}
	current->waitable = waitable;
	current->context = context;
	current->routine = routine;

	LIST_INSERT_HEAD(&WEHead, current, link);

	return (0);
}

/*
 * Remove a waitable object
 */
DWORD
scheduler_remove_waitable(HANDLE waitable)
{
	WaitableEntry *current;

	LIST_FOREACH(current, &WEHead, link)
	    if (current->waitable == waitable)
		    break;

	if (current == NULL)
		return (ENOENT);

	LIST_REMOVE(current, link);
	free(current);
	nentries--;
	return (0);
}

/*
 * Runs the scheduler, checking waitable objects for data
 */
DWORD
scheduler_run(Remote *remote, DWORD timeout)
{
	WaitableEntry *current;
	int ret, i, found, idx = 0;

	if (LIST_EMPTY(&WEHead) || polltable == NULL)
		return (ENOENT);
	
	LIST_FOREACH(current, &WEHead, link) {
		polltable[idx].fd = current->waitable;
		polltable[idx].events = POLLRDNORM;
		polltable[idx].revents = 0;
		idx++;
	}
	
	if ((ret = poll(polltable, idx, timeout)) == 0)
		return (ENOENT);
	
	for (found = i = 0; i < idx && found < ret; i++) {
		if (polltable[i].revents) {
			LIST_FOREACH(current, &WEHead, link)
			    if (current->waitable == polltable[i].fd)
				    break;
			ret = current->routine(remote, current->context);
		}
	}
	/*
	 * return last result
	 */
	return (ret);
}


