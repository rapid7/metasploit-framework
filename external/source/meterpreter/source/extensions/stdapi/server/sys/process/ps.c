#include "precomp.h"
#include "ps.h"
#include "./../session.h"
#include "./../../../../../common/arch/win/i386/base_inject.h"

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
DWORD ps_inject( DWORD dwPid, DLL_BUFFER * pDllBuffer, char * cpCommandLine )
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

		dwResult = inject_dll( dwPid, lpDllBuffer, dwDllLenght, cpCommandLine );

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

/*
 * Attempt to get the processes path and name.
 * First, try psapi!GetModuleFileNameExA (Windows 2000/XP/2003/Vista/2008/7 but cant get x64 process paths from a wow64 process)
 * Secondly, try kernel32!QueryFullProcessImageNameA (Windows Vista/2008/7)
 * Thirdly, try psapi!GetProcessImageFileNameA (Windows XP/2003/Vista/2008/7 - returns native path)
 * If that fails then try to read the path via the process's PEB. (Windows NT4 and above).
 * Note: cpExeName is optional and only retrieved by parsing the PEB as the toolhelp/psapi techniques can get the name easier.
 */
BOOL ps_getpath( DWORD pid, char * cpExePath, DWORD dwExePathSize, char * cpExeName, DWORD dwExeNameSize )
{
	BOOL success    = FALSE;
	HANDLE hProcess = NULL;
	HMODULE hPsapi  = NULL;
	HMODULE hNtdll  = NULL;
	// make these static to avoid some overhead when resolving due to the repeated calls to ps_getpath fo a ps command...
	static GETMODULEFILENAMEEXA pGetModuleFileNameExA             = NULL;
	static GETPROCESSIMAGEFILENAMEA pGetProcessImageFileNameA     = NULL;
	static QUERYFULLPROCESSIMAGENAMEA pQueryFullProcessImageNameA = NULL;

	do
	{
		if( !cpExePath || !dwExePathSize )
			break;

		memset( cpExePath, 0, dwExePathSize );

		hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );
		if( !hProcess )
			break;
				
		// first, try psapi!GetModuleFileNameExA (Windows 2000/XP/2003/Vista/2008/7 but cant get x64 process paths from a wow64 process)
		hPsapi = LoadLibrary( "psapi" );
		if( hPsapi )
		{
			if( !pGetModuleFileNameExA )
				pGetModuleFileNameExA = (GETMODULEFILENAMEEXA)GetProcAddress( hPsapi, "GetModuleFileNameExA" );

			if( pGetModuleFileNameExA )
			{	
				if( pGetModuleFileNameExA( hProcess, NULL, cpExePath, dwExePathSize ) )
					success = TRUE;	
			}
		}

		// secondly, try kernel32!QueryFullProcessImageNameA (Windows Vista/2008/7)
		if( !success )
		{
			DWORD dwSize   = dwExePathSize;
			HANDLE hKernel = LoadLibraryA( "kernel32" );

			if( !pQueryFullProcessImageNameA )
				pQueryFullProcessImageNameA = (QUERYFULLPROCESSIMAGENAMEA)GetProcAddress( hKernel, "QueryFullProcessImageNameA" );
			
			if( pQueryFullProcessImageNameA )
			{
				if( pQueryFullProcessImageNameA( hProcess, 0, cpExePath, &dwSize ) )
					success = TRUE;
			}

			if( hKernel )
				FreeLibrary( hKernel );
		}	

		// thirdly, try psapi!GetProcessImageFileNameA (Windows XP/2003/Vista/2008/7 - returns a native path not a win32 path)
		if( !success && hPsapi )
		{
			if( !pGetProcessImageFileNameA )
				pGetProcessImageFileNameA = (GETPROCESSIMAGEFILENAMEA)GetProcAddress( hPsapi, "GetProcessImageFileNameA" );

			if( pGetProcessImageFileNameA )
			{
				if( pGetProcessImageFileNameA( hProcess, cpExePath, dwExePathSize ) )
					success = TRUE;
			}
		}

		// finally if all else has failed, manually pull the exe path/name out of th PEB...
		if( !success )
		{
			WCHAR * wcImagePathName                              = NULL;
			NTQUERYINFORMATIONPROCESS pNtQueryInformationProcess = NULL;
			DWORD dwSize                                         = 0;
			PROCESS_BASIC_INFORMATION BasicInformation           = {0};
			RTL_USER_PROCESS_PARAMETERS params                   = {0};
			_PEB peb                                             = {0};

			hNtdll = LoadLibraryA( "ntdll" );
			if( !hNtdll )
				break;

			pNtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)GetProcAddress( hNtdll, "NtQueryInformationProcess" );
			if( !pNtQueryInformationProcess )
				break;

			if( pNtQueryInformationProcess( hProcess, 0, &BasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &dwSize ) != ERROR_SUCCESS )
				break;

			if( !BasicInformation.PebBaseAddress )
				break;

			if( !ReadProcessMemory( hProcess, BasicInformation.PebBaseAddress, &peb, 64, NULL ) ) // (just read in the first 64 bytes of PEB)
				break;

			if( !peb.lpProcessParameters )
				break;

			if( !ReadProcessMemory( hProcess, peb.lpProcessParameters, &params, sizeof(params), NULL ) )
				break;

			wcImagePathName = (WCHAR *)malloc( params.ImagePathName.Length );
			if( wcImagePathName )
			{
				if( ReadProcessMemory( hProcess, params.ImagePathName.Buffer, wcImagePathName, params.ImagePathName.Length, NULL ) )
				{
					char * name = NULL;

					WideCharToMultiByte( CP_ACP, 0, wcImagePathName, (int)(params.ImagePathName.Length / sizeof(WCHAR)), cpExePath, dwExePathSize, NULL, NULL );

					if( cpExeName )
					{
						name = strrchr( cpExePath, '\\' );
						if( name )
							strncpy( cpExeName, name+1, dwExeNameSize );
					}
					success = TRUE;
				}
				free( wcImagePathName );
			}
		}

	} while( 0 );

	if( hPsapi )
		FreeLibrary( hPsapi );

	if( hNtdll )
		FreeLibrary( hNtdll );

	if( hProcess )
		CloseHandle( hProcess );

	if( !success && cpExePath )
		memset( cpExePath, 0, dwExePathSize );

	return success;
}


/*
 * Attempt to get the username associated with the given pid.
 */
BOOL ps_getusername( DWORD pid, char * cpUserName, DWORD dwUserNameSize )
{
	BOOL success                = FALSE;
	HANDLE hProcess             = NULL;
	HANDLE hToken               = NULL;
	TOKEN_USER * pUser          = NULL;
	SID_NAME_USE peUse          = 0;
	DWORD dwUserLength          = 0;
	DWORD dwDomainLength        = 0;
	DWORD dwLength              = 0;
	char cUser[512]             = {0};
	char cDomain[512]           = {0};

	do
	{
		if( !cpUserName || !dwUserNameSize )
			break;

		memset( cpUserName, 0, dwUserNameSize );
		
		hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid );
		if( !hProcess )
			break;

		if( !OpenProcessToken( hProcess, TOKEN_QUERY, &hToken ) ) 
			break;

		GetTokenInformation( hToken, TokenUser, NULL, 0, &dwLength );

		pUser = (TOKEN_USER *)malloc( dwLength );
		if( !pUser )
			break;

		if( !GetTokenInformation( hToken, TokenUser, pUser, dwLength, &dwLength ) )
			break;

		dwUserLength   = sizeof( cUser );
		dwDomainLength = sizeof( cDomain );

		if( !LookupAccountSid( NULL, pUser->User.Sid, cUser, &dwUserLength, cDomain, &dwDomainLength, &peUse ) )
			break;

		_snprintf( cpUserName, dwUserNameSize-1, "%s\\%s", cDomain, cUser );

		success = TRUE;

	} while(0);
	
	if( pUser )
		free( pUser );

	if( hToken )
		CloseHandle( hToken );

	if( hProcess )
		CloseHandle( hProcess );

	return success;
}

/*
 * Add the details of a process to the response.
 */
VOID ps_addresult( Packet * response, DWORD dwPid, DWORD dwParentPid, char * cpExeName, char * cpExePath, char * cpUserName, DWORD dwProcessArch )
{
	Tlv entries[7]    = {0};
	DWORD dwSessionId = 0;

	do
	{
		if( !response )
			break;

		dwSessionId = session_id( dwPid );

		dwPid                    = htonl( dwPid );
		entries[0].header.type   = TLV_TYPE_PID;
		entries[0].header.length = sizeof( DWORD );
		entries[0].buffer        = (PUCHAR)&dwPid;

		if( !cpExeName )
			cpExeName = "";
		entries[1].header.type   = TLV_TYPE_PROCESS_NAME;
		entries[1].header.length = (DWORD)strlen( cpExeName ) + 1;
		entries[1].buffer        = cpExeName;
		
		if( !cpExePath )
			cpExePath = "";
		entries[2].header.type   = TLV_TYPE_PROCESS_PATH;
		entries[2].header.length = (DWORD)strlen( cpExePath ) + 1;
		entries[2].buffer        = cpExePath;
		
		if( !cpUserName )
			cpUserName = "";
		entries[3].header.type   = TLV_TYPE_USER_NAME;
		entries[3].header.length = (DWORD)strlen( cpUserName ) + 1;
		entries[3].buffer        = cpUserName;

		dwProcessArch            = htonl( dwProcessArch );
		entries[4].header.type   = TLV_TYPE_PROCESS_ARCH;
		entries[4].header.length = sizeof( DWORD );
		entries[4].buffer        = (PUCHAR)&dwProcessArch;

		dwParentPid              = htonl( dwParentPid );
		entries[5].header.type   = TLV_TYPE_PARENT_PID;
		entries[5].header.length = sizeof( DWORD );
		entries[5].buffer        = (PUCHAR)&dwParentPid;
		
		dwSessionId              = htonl( dwSessionId );
		entries[6].header.type   = TLV_TYPE_PROCESS_SESSION;
		entries[6].header.length = sizeof( DWORD );
		entries[6].buffer        = (PUCHAR)&dwSessionId;

		packet_add_tlv_group( response, TLV_TYPE_PROCESS_GROUP, entries, 7 );

	} while(0);

}

/*
 * Generate a process list via the kernel32!CreateToolhelp32Snapshot method. Works on Windows 2000 and above.
 */
DWORD ps_list_via_toolhelp( Packet * response )
{
	DWORD result                                       = ERROR_INVALID_HANDLE;
	CREATETOOLHELP32SNAPSHOT pCreateToolhelp32Snapshot = NULL;
	PROCESS32FIRST pProcess32First                     = NULL;
	PROCESS32NEXT pProcess32Next                       = NULL;
	HANDLE hProcessSnap                                = NULL;
	HMODULE hKernel                                    = NULL;
	PROCESSENTRY32 pe32                                = {0};

	do
	{
		hKernel = LoadLibrary( "kernel32" );
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

		result = ERROR_SUCCESS;
		
		do
		{
			DWORD dwProcessArch  = PROCESS_ARCH_UNKNOWN;
			char cExePath[1024]  = {0};
			char cUserName[1024] = {0};
			Tlv entries[5]       = {0};

			ps_getpath( pe32.th32ProcessID, (char *)&cExePath, 1024, NULL, 0 );

			ps_getusername( pe32.th32ProcessID, (char *)&cUserName, 1024 );

			dwProcessArch = ps_getarch( pe32.th32ProcessID );

			ps_addresult( response, pe32.th32ProcessID, pe32.th32ParentProcessID, pe32.szExeFile, cExePath, cUserName, dwProcessArch );

		} while( pProcess32Next( hProcessSnap, &pe32 ) );

	} while(0);

	if( hProcessSnap )
		CloseHandle( hProcessSnap );
	
	if( hKernel )
		FreeLibrary( hKernel );

	return result;
}


/*
 * Generate a process list via the psapi!EnumProcesses method. 
 * Works on Windows 2000 and above and NT4 if the PSAPI patch has been applied.
 * Note: This method cant determine the parent process id (default to 0).
 */
DWORD ps_list_via_psapi( Packet * response )
{
	DWORD result                           = ERROR_INVALID_HANDLE;
	HMODULE hPsapi                         = NULL;
	ENUMPROCESSES pEnumProcesses           = NULL;
	ENUMPROCESSMODULES pEnumProcessModules = NULL;
	GETMODULEBASENAMEA pGetModuleBaseNameA = NULL;
	DWORD dwProcessIds[1024]               = {0};
	DWORD dwBytesReturned                  = 0;
	DWORD index                            = 0;

	do
	{
		hPsapi = LoadLibrary( "psapi" );
		if( !hPsapi )
			break;

		pEnumProcesses      = (ENUMPROCESSES)GetProcAddress( hPsapi, "EnumProcesses" );
		pEnumProcessModules = (ENUMPROCESSMODULES)GetProcAddress( hPsapi, "EnumProcessModules" );
		pGetModuleBaseNameA = (GETMODULEBASENAMEA)GetProcAddress( hPsapi, "GetModuleBaseNameA" );

		if( !pEnumProcesses || !pEnumProcessModules || !pGetModuleBaseNameA )
			break;

		if( !pEnumProcesses( (DWORD *)&dwProcessIds, sizeof(dwProcessIds), &dwBytesReturned ) )
			break;

		result = ERROR_SUCCESS;

		for( index=0 ; index<(dwBytesReturned/sizeof(DWORD)); index++ )
		{
			HANDLE hProcess      = NULL;
			HMODULE hModule      = NULL;
			DWORD dwProcessArch  = PROCESS_ARCH_UNKNOWN;
			char cExeName[1024]  = {0};
			char cExePath[1024]  = {0};
			char cUserName[1024] = {0};
			Tlv entries[5]       = {0};
			DWORD dwNeeded       = 0;

			do
			{
				hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessIds[index] );
				if( !hProcess )
					break;

				if( !pEnumProcessModules( hProcess, &hModule, sizeof(hModule), &dwNeeded ) )
					break;

				pGetModuleBaseNameA( hProcess, hModule, cExeName, 1024 );

			} while(0);

			if( hProcess )
				CloseHandle( hProcess );

			ps_getpath( dwProcessIds[index], (char *)&cExePath, 1024, NULL, 0 );

			ps_getusername( dwProcessIds[index], (char *)&cUserName, 1024 );

			dwProcessArch = ps_getarch( dwProcessIds[index] );

			ps_addresult( response, dwProcessIds[index], 0, cExePath, cExePath, cUserName, dwProcessArch );
		}

	} while(0);

	if( hPsapi )
		FreeLibrary( hPsapi );

	return result;
}

/*
 * Generate a process list by brute forcing the process id's. If we can open the
 * process with PROCESS_QUERY_INFORMATION access we can assume the pid exists.
 */
DWORD ps_list_via_brute( Packet * response )
{
	DWORD result = ERROR_SUCCESS;
	DWORD pid    = 0;
	
	for( pid=0 ; pid<0xFFFF ; pid++ )
	{
		HANDLE hProcess      = NULL;
		DWORD dwProcessArch  = PROCESS_ARCH_UNKNOWN;
		char cExeName[1024]  = {0};
		char cExePath[1024]  = {0};
		char cUserName[1024] = {0};
		Tlv entries[5]       = {0};

		hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid );
		if( !hProcess )
			continue;

		CloseHandle( hProcess );

		ps_getpath( pid, (char *)&cExePath, 1024, (char *)&cExeName, 1024 );

		ps_getusername( pid, (char *)&cUserName, 1024 );

		dwProcessArch = ps_getarch( pid );

		ps_addresult( response, pid, 0, cExeName, cExePath, cUserName, dwProcessArch );
	}

	return result;
}
