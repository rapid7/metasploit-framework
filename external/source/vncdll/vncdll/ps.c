#include "loader.h"
#include "ps.h"
#include "session.h"
#include "inject.h"

/*
 * Get the arch type (either x86 or x64) for a given PE (either PE32 or PE64) DLL image.
 */
DWORD ps_getarch_dll( LPVOID lpDllBuffer )
{
	DWORD dwDllArch             = PROCESS_ARCH_UNKNOWN;
	PIMAGE_NT_HEADERS pNtHeader = NULL;

	do
	{
		if( !lpDllBuffer )
			break;

		// get the File Offset of the modules NT Header
		pNtHeader = (PIMAGE_NT_HEADERS)( ((UINT_PTR)lpDllBuffer) + ((PIMAGE_DOS_HEADER)lpDllBuffer)->e_lfanew );
		
		if( pNtHeader->OptionalHeader.Magic == 0x010B ) // PE32
			dwDllArch = PROCESS_ARCH_X86;
		else if( pNtHeader->OptionalHeader.Magic == 0x020B ) // PE64
			dwDllArch = PROCESS_ARCH_X64;

	} while( 0 );

	return dwDllArch;
}

/*
 * Inject a DLL into another process via Reflective DLL Injection.
 */
DWORD ps_inject( DWORD dwPid, DLL_BUFFER * pDllBuffer )
{
	DWORD dwResult     = ERROR_ACCESS_DENIED;
	DWORD dwPidArch    = PROCESS_ARCH_UNKNOWN;
	DWORD dwDllArch    = PROCESS_ARCH_UNKNOWN;
	LPVOID lpDllBuffer = NULL;
	DWORD dwDllLenght  = 0;

	do
	{
		if( !pDllBuffer )
			BREAK_WITH_ERROR( "[PS] ps_inject_dll. No Dll buffer specified", ERROR_INVALID_PARAMETER ); 

		dwPidArch = ps_getarch( dwPid );

		if( dwPidArch == PROCESS_ARCH_X86 )
		{
			lpDllBuffer = pDllBuffer->lpPE32DllBuffer;
			dwDllLenght = pDllBuffer->dwPE32DllLenght;
		}
		else if( dwPidArch == PROCESS_ARCH_X64 )
		{
			lpDllBuffer = pDllBuffer->lpPE64DllBuffer;
			dwDllLenght = pDllBuffer->dwPE64DllLenght;
		}
		else
		{
			BREAK_WITH_ERROR( "[PS] ps_inject_dll. Unable to determine target pid arhitecture", ERROR_INVALID_DATA ); 
		}

		dwDllArch = ps_getarch_dll( lpDllBuffer );
		if( dwDllArch == PROCESS_ARCH_UNKNOWN )
			BREAK_WITH_ERROR( "[PS] ps_inject_dll. Unable to determine DLL arhitecture", ERROR_BAD_FORMAT ); 

		if( dwDllArch != dwPidArch )
			BREAK_WITH_ERROR( "[PS] ps_inject_dll. pid/dll architecture mixup", ERROR_BAD_ENVIRONMENT ); 

		dwResult = inject_dll( dwPid, lpDllBuffer, dwDllLenght );

	} while( 0 );

	return dwResult;
}

/*
 * Get the architecture of the given process.
 */
DWORD ps_getarch( DWORD dwPid )
{
	DWORD result                   = PROCESS_ARCH_UNKNOWN;
	static DWORD dwNativeArch      = PROCESS_ARCH_UNKNOWN;
	HANDLE hKernel                 = NULL;
	HANDLE hProcess                = NULL;
	ISWOW64PROCESS pIsWow64Process = NULL;
	BOOL bIsWow64                  = FALSE;

	do
	{
		// grab the native systems architecture the first time we use this function...
		if( dwNativeArch == PROCESS_ARCH_UNKNOWN )
			dwNativeArch = ps_getnativearch();

		// first we default to 'x86' as if kernel32!IsWow64Process is not present then we are on an older x86 system.
		result = PROCESS_ARCH_X86;

		hKernel = LoadLibraryA( "kernel32.dll" );
		if( !hKernel )
			break;

		pIsWow64Process = (ISWOW64PROCESS)GetProcAddress( hKernel, "IsWow64Process" );
		if( !pIsWow64Process )
			break;
		
		// now we must default to an unknown architecture as the process may be either x86/x64 and we may not have the rights to open it
		result = PROCESS_ARCH_UNKNOWN;

		hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, dwPid );
		if( !hProcess )
		{
			hProcess = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid );
			if( !hProcess )
				break;
		}

		if( !pIsWow64Process( hProcess, &bIsWow64 ) )
			break;

		if( bIsWow64 )
			result = PROCESS_ARCH_X86;
		else
			result = dwNativeArch;

	} while( 0 );

	if( hProcess )
		CloseHandle( hProcess );

	if( hKernel )
		FreeLibrary( hKernel );

	return result;
}

/*
 * Get the native architecture of the system we are running on.
 */
DWORD ps_getnativearch( VOID )
{
	HANDLE hKernel                           = NULL;
	GETNATIVESYSTEMINFO pGetNativeSystemInfo = NULL;
	DWORD dwNativeArch                       = PROCESS_ARCH_UNKNOWN;
	SYSTEM_INFO SystemInfo                   = {0};

	do
	{
		// default to 'x86' as if kernel32!GetNativeSystemInfo is not present then we are on an old x86 system.
		dwNativeArch = PROCESS_ARCH_X86;

		hKernel = LoadLibraryA( "kernel32.dll" );
		if( !hKernel )
			break;

		pGetNativeSystemInfo = (GETNATIVESYSTEMINFO)GetProcAddress( hKernel, "GetNativeSystemInfo" );
		if( !pGetNativeSystemInfo )
			break;
				
		pGetNativeSystemInfo( &SystemInfo );
		switch( SystemInfo.wProcessorArchitecture )
		{
			case PROCESSOR_ARCHITECTURE_AMD64:
				dwNativeArch = PROCESS_ARCH_X64;
				break;
			case PROCESSOR_ARCHITECTURE_IA64:
				dwNativeArch = PROCESS_ARCH_IA64;
				break;
			case PROCESSOR_ARCHITECTURE_INTEL:
				dwNativeArch = PROCESS_ARCH_X86;
				break;
			default:
				dwNativeArch = PROCESS_ARCH_UNKNOWN;
				break;
		}

	} while( 0 );

	if( hKernel )
		FreeLibrary( hKernel );

	return dwNativeArch;
}
