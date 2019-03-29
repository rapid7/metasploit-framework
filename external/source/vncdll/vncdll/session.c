#include "loader.h"
#include "session.h"

/*
 * Returns the session id associated with a process.
 * Returns -1 if we cant determine the session id (e.g. insufficient privileges).
 * Returns 0 by default on NT4.
 */
DWORD session_id( DWORD dwProcessId )
{
	typedef BOOL (WINAPI * PROCESSIDTOSESSIONID)( DWORD pid, LPDWORD id );

	static PROCESSIDTOSESSIONID pProcessIdToSessionId = NULL;
	HMODULE hKernel   = NULL;
	DWORD dwSessionId = 0;

	do
	{
		if( !pProcessIdToSessionId )
		{
			hKernel = LoadLibraryA( "kernel32.dll" );
			if( hKernel )
				pProcessIdToSessionId = (PROCESSIDTOSESSIONID)GetProcAddress( hKernel, "ProcessIdToSessionId" );
		}

		if( !pProcessIdToSessionId )
			break;

		if( !pProcessIdToSessionId( dwProcessId, &dwSessionId ) )
			dwSessionId = -1;

	} while( 0 );

	if( hKernel )
		FreeLibrary( hKernel );

	return dwSessionId;
}

/*
 * Returns the session id attached to the physical console.
 * Returns 0 by default on NT4 and 2000.
 */
DWORD session_activeid()
{
	typedef DWORD (WINAPI * WTSGETACTIVECONSOLESESSIONID )( VOID );

	static WTSGETACTIVECONSOLESESSIONID pWTSGetActiveConsoleSessionId = NULL;
	HMODULE hKernel   = NULL;
	DWORD dwSessionId = 0;

	do
	{
		if( !pWTSGetActiveConsoleSessionId )
		{
			hKernel = LoadLibraryA( "kernel32.dll" );
			if( hKernel )
				pWTSGetActiveConsoleSessionId = (WTSGETACTIVECONSOLESESSIONID)GetProcAddress( hKernel, "WTSGetActiveConsoleSessionId" );
		}

		if( !pWTSGetActiveConsoleSessionId )
			break;

		dwSessionId = pWTSGetActiveConsoleSessionId();

	} while( 0 );

	if( hKernel )
		FreeLibrary( hKernel );

	return dwSessionId;
}

/*
 * On NT4 its we bruteforce the process list as kernel32!CreateToolhelp32Snapshot is not available.
 */
DWORD _session_inject_bruteforce( DWORD dwSessionId, DLL_BUFFER * pDllBuffer )
{
	DWORD dwResult = ERROR_INVALID_HANDLE;
	DWORD pid      = 0;

	do
	{
		for( pid=0 ; pid<0xFFFF ; pid++ )
		{
			HANDLE hProcess = NULL;

			hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid );
			if( !hProcess )
				continue;

			CloseHandle( hProcess );

			if( dwSessionId == session_id( pid ) )
			{
				dwResult = ps_inject( pid, pDllBuffer );
				if( dwResult == ERROR_SUCCESS )
				{
					dprintf( "[SESSION] _session_inject_bruteforce. Injected into process %d", pid );
					break;
				}
			}
		}

	} while( 0 );

	return dwResult;
}

/*
 * Inject an arbitrary DLL into a process running in specific Windows session.
 */
DWORD session_inject( DWORD dwSessionId, DLL_BUFFER * pDllBuffer )
{
	DWORD dwResult                                     = ERROR_INVALID_HANDLE;
	CREATETOOLHELP32SNAPSHOT pCreateToolhelp32Snapshot = NULL;
	PROCESS32FIRST pProcess32First                     = NULL;
	PROCESS32NEXT pProcess32Next                       = NULL;
	HANDLE hProcessSnap                                = NULL;
	HMODULE hKernel                                    = NULL;
	HANDLE hToken                                      = NULL;
	BOOL bUseBruteForce                                = TRUE;
	PROCESSENTRY32 pe32                                = {0};

	do
	{
		// If we can, get SeDebugPrivilege...
		if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
		{
			TOKEN_PRIVILEGES priv = {0};

			priv.PrivilegeCount           = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			
			if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) )
			{
				if( AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL ) );
					dprintf("[SESSION] session_inject. Got SeDebugPrivilege!" );
			}

			CloseHandle( hToken );
		}

		hKernel = LoadLibraryA( "kernel32" );
		if( !hKernel )
			break;

		pCreateToolhelp32Snapshot = (CREATETOOLHELP32SNAPSHOT)GetProcAddress( hKernel, "CreateToolhelp32Snapshot" );
		pProcess32First           = (PROCESS32FIRST)GetProcAddress( hKernel, "Process32First" );
		pProcess32Next            = (PROCESS32NEXT)GetProcAddress( hKernel, "Process32Next" );

		if( !pCreateToolhelp32Snapshot || !pProcess32First || !pProcess32Next )
			break;

		hProcessSnap = pCreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		if( hProcessSnap == INVALID_HANDLE_VALUE )
			break;

		pe32.dwSize = sizeof( PROCESSENTRY32 );

		if( !pProcess32First( hProcessSnap, &pe32 ) )
			break;
				
		bUseBruteForce = FALSE;
		
		do
		{
			if( dwSessionId == session_id( pe32.th32ProcessID ) )
			{
				// On Windows 2008R2 we Blue Screen the box if we inject via APC injection 
				// into the target sessions instance of csrss.exe!!! so we filter it out...
				if( strstr( pe32.szExeFile, "csrss.exe" ) )
					continue;

				dwResult = ps_inject( pe32.th32ProcessID, pDllBuffer );
				if( dwResult == ERROR_SUCCESS )
				{
					dprintf( "[SESSION] session_inject. Injected into process %d (%s)", pe32.th32ProcessID, pe32.szExeFile );
					break;
				}
			}
		} while( pProcess32Next( hProcessSnap, &pe32 ) );

	} while( 0 );

	if( hProcessSnap )
		CloseHandle( hProcessSnap );
	
	if( hKernel )
		FreeLibrary( hKernel );

	// On NT4 we must brute force the process list...
	if( bUseBruteForce )
		dwResult = _session_inject_bruteforce( dwSessionId, pDllBuffer );

	return dwResult;
}

