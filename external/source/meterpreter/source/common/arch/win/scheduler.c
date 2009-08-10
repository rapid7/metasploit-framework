#include "common.h"

typedef struct _WaitableEntry
{
	HANDLE                waitable;
	LPVOID                context;
	WaitableNotifyRoutine routine;
} WaitableEntry;

WaitableEntry *waitableArray = NULL;
HANDLE *waitableHandleArray  = NULL;
HANDLE schedulerWakeUpEvent  = NULL;
DWORD numWaitableEntries     = 0;

/*
 * Rebuilds the handle array
 */
VOID scheduler_build_handle_array()
{
	DWORD index = 0;

	if (!schedulerWakeUpEvent)
		schedulerWakeUpEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	if (waitableHandleArray)
		free(waitableHandleArray);

	waitableHandleArray = (HANDLE *)malloc((numWaitableEntries+1) *
			sizeof(HANDLE));

	if (waitableHandleArray)
	{
		for (index = 0;
		     index < numWaitableEntries;
		     index++)
			waitableHandleArray[index] = waitableArray[index].waitable;

		// Finally, add the wake up event to the mix.
		waitableHandleArray[index] = schedulerWakeUpEvent;
	}

	if (schedulerWakeUpEvent)
		SetEvent(schedulerWakeUpEvent);
}

/*
 * Insert a waitable object for checking and processing
 */
DWORD scheduler_insert_waitable(HANDLE waitable, LPVOID context,
		WaitableNotifyRoutine routine)
{
	WaitableEntry *newArray = NULL;
	DWORD res = ERROR_SUCCESS;

	do
	{
		// Allocate space for storing the handle in the waitable array
		if (!waitableArray)
		{
			if (!(newArray = (WaitableEntry *)malloc(
				sizeof(WaitableEntry))))
			{
				res = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}
		}
		else if (!(newArray = (WaitableEntry *)realloc(waitableArray,
				sizeof(WaitableEntry) * (numWaitableEntries+1))))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Put the waitable handle into the waitable handle array
		newArray[numWaitableEntries].waitable = waitable;
		newArray[numWaitableEntries].context  = context;
		newArray[numWaitableEntries].routine  = routine;
		waitableArray                         = newArray;

		// Increment the number of entries
		numWaitableEntries++;

	} while (0);

	scheduler_build_handle_array();

	return res;
}

/*
 * Remove a waitable object
 */
DWORD scheduler_remove_waitable(HANDLE waitable)
{
	DWORD index = 0, numItemsToRemove = 0;
	WaitableEntry *newArray = NULL;
	BOOL found = FALSE;
		
	// Enumerate the waitable handle array, flushing out all
	// entries with the provided handle
	for (index = 0;
	     index < numWaitableEntries;
	     index++)
	{
		if (waitableArray[index].waitable != waitable)
			continue;

		waitableArray[index].waitable = NULL;

		numItemsToRemove++;
		
		found = TRUE;
	}

	// Repopulate the array of waitable items with the provided
	// handle removed.
	if ((newArray = (WaitableEntry *)malloc(sizeof(WaitableEntry) *
			(numWaitableEntries - numItemsToRemove))))
	{
		DWORD newIndex;

		for (index = 0, newIndex = 0; 
		     index < numWaitableEntries;
		     index++)
		{
			if (!waitableArray[index].waitable)
				continue;

			newArray[newIndex++] = waitableArray[index];
		}

		// Destroy the waitable array
		free(waitableArray);

		// Set the waitable array to the new array
		waitableArray       = newArray;
		numWaitableEntries -= numItemsToRemove;
	}

	scheduler_build_handle_array();

	return (found) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
}

/*
 * Runs the scheduler, checking waitable objects for data
 */
DWORD scheduler_run(Remote *remote, DWORD timeout)
{
	DWORD res;

	if (waitableHandleArray)
	{
		DWORD index;

		res = WaitForMultipleObjects(numWaitableEntries + 1, 
				waitableHandleArray, FALSE, timeout);

		// If one of the objects signaled data
		if ((res >= WAIT_OBJECT_0) &&
		    ((index = res - WAIT_OBJECT_0) < numWaitableEntries))
			res = waitableArray[index].routine(remote, 
					waitableArray[index].context);
		else if (res >= WAIT_OBJECT_0)
			res = ERROR_SUCCESS;
	}

	return res;
}
