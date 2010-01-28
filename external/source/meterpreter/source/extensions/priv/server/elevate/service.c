#include "precomp.h"
#include "service.h"

/*
 * Start a service which has allready been created.
 */
DWORD service_start( char * cpName )
{
	DWORD dwResult  = ERROR_SUCCESS;
	HANDLE hManager = NULL;
	HANDLE hService = NULL;

	do
	{
		if( !cpName )
			BREAK_WITH_ERROR( "[SERVICE] service_start. cpName is NULL", ERROR_INVALID_HANDLE );

		hManager = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if( !hManager )
			BREAK_ON_ERROR( "[SERVICE] service_start. OpenSCManagerA failed" );
		
		hService = OpenServiceA( hManager, cpName, SERVICE_START );
		if( !hService )
			BREAK_ON_ERROR( "[SERVICE] service_start. OpenServiceA failed" );

		if( !StartService( hService, 0, NULL ) )
			BREAK_ON_ERROR( "[SERVICE] service_start. StartService failed" );

	} while( 0 );

	if( hService )
		CloseServiceHandle( hService ); 

	if( hManager )
		CloseServiceHandle( hManager ); 

	SetLastError( dwResult );

	return dwResult;
}

/*
 * Stop a service.
 */
DWORD service_stop( char * cpName )
{
	DWORD dwResult                = ERROR_SUCCESS;
	HANDLE hManager               = NULL;
	HANDLE hService               = NULL;
	SERVICE_STATUS_PROCESS status = {0};
	DWORD dwBytes                 = 0;
	DWORD dwStartTime             = 0;
	DWORD dwTimeout               = 30000; // 30 seconds

	do
	{
		if( !cpName )
			BREAK_WITH_ERROR( "[SERVICE] service_stop. cpName is NULL", ERROR_INVALID_HANDLE );

		hManager = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if( !hManager )
			BREAK_ON_ERROR( "[SERVICE] service_stop. OpenSCManagerA failed" );
		
		hService = OpenServiceA( hManager, cpName, SERVICE_STOP | SERVICE_QUERY_STATUS ); 
		if( !hService )
			BREAK_ON_ERROR( "[SERVICE] service_stop. OpenServiceA failed" );

		if( !ControlService( hService, SERVICE_CONTROL_STOP, (SERVICE_STATUS *)&status ) )
			BREAK_ON_ERROR( "[SERVICE] service_stop. ControlService STOP failed" );
		
		dwStartTime = GetTickCount();

		while( TRUE ) 
		{
			if( !QueryServiceStatusEx( hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &dwBytes ) )
				BREAK_ON_ERROR( "[SERVICE] service_stop. QueryServiceStatusEx failed" );
			
			if( status.dwCurrentState == SERVICE_STOPPED )
				break;

			if( ( GetTickCount() - dwStartTime ) > dwTimeout )
				BREAK_WITH_ERROR( "[SERVICE] service_stop. Timeout reached", WAIT_TIMEOUT );
			
			Sleep( status.dwWaitHint );
		}

	} while( 0 );

	if( hService )
		CloseServiceHandle( hService ); 

	if( hManager )
		CloseServiceHandle( hManager ); 

	SetLastError( dwResult );

	return dwResult;
}

/*
 * Create a new service.
 */
DWORD service_create( char * cpName, char * cpPath )
{
	DWORD dwResult  = ERROR_SUCCESS;
	HANDLE hManager = NULL;
	HANDLE hService = NULL;

	do
	{
		if( !cpName || !cpPath )
			BREAK_WITH_ERROR( "[SERVICE] service_create. cpName/cpPath is NULL", ERROR_INVALID_HANDLE );

		hManager = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if( !hManager )
			BREAK_ON_ERROR( "[SERVICE] service_create. OpenSCManagerA failed" );
		
		hService = CreateServiceA( hManager, cpName, NULL, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, cpPath, NULL, NULL, NULL, NULL, NULL );
		if( !hService )
			BREAK_ON_ERROR( "[SERVICE] service_create. CreateServiceA failed" );
		
	} while( 0 );

	if( hService )
		CloseServiceHandle( hService ); 

	if( hManager )
		CloseServiceHandle( hManager ); 

	SetLastError( dwResult );

	return dwResult;
}

/*
 * Destroy an existing service.
 */
DWORD service_destroy( char * cpName )
{
	DWORD dwResult  = ERROR_SUCCESS;
	HANDLE hManager = NULL;
	HANDLE hService = NULL;

	do
	{
		if( !cpName )
			BREAK_WITH_ERROR( "[SERVICE] service_destroy. cpName is NULL", ERROR_INVALID_HANDLE );

		hManager = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if( !hManager )
			BREAK_ON_ERROR( "[SERVICE] service_destroy. OpenSCManagerA failed" );
		
		hService = OpenServiceA( hManager, cpName, DELETE ); 
		if( !hService )
			BREAK_ON_ERROR( "[SERVICE] service_stop. OpenServiceA failed" );

		if( !DeleteService( hService ) )
			BREAK_ON_ERROR( "[SERVICE] service_destroy. DeleteService failed" );

	} while( 0 );

	if( hService )
		CloseServiceHandle( hService ); 

	if( hManager )
		CloseServiceHandle( hManager ); 

	SetLastError( dwResult );

	return dwResult;
}
