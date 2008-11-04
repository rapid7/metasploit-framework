//===============================================================================================//
// Copyright (c) 2008, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "GetProcAddressR.h"
//===============================================================================================//
// We implement a minimal GetProcAddress to avoid using the native kernel32!GetProcAddress which
// wont be able to resolve exported addresses in reflectivly loaded librarys.
FARPROC WINAPI GetProcAddressR( HANDLE hModule, LPCSTR lpProcName )
{
	DWORD dwLibraryAddress = 0;
	FARPROC fpResult       = NULL;

	if( hModule == NULL )
		return NULL;

	// a module handle is really its base address
	dwLibraryAddress = (DWORD)hModule;

	__try
	{
		DWORD dwAddressArray = 0;
		DWORD dwNameArray    = 0;
		DWORD dwNameOrdinals = 0;
		PIMAGE_NT_HEADERS32 pNtHeaders           = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory     = NULL;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
			
		// get the VA of the modules NT Header
		pNtHeaders = (PIMAGE_NT_HEADERS32)(dwLibraryAddress + ((PIMAGE_DOS_HEADER)dwLibraryAddress)->e_lfanew);

		pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

		// get the VA of the export directory
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)( dwLibraryAddress + pDataDirectory->VirtualAddress );
			
		// get the VA for the array of addresses
		dwAddressArray = ( dwLibraryAddress + pExportDirectory->AddressOfFunctions );

		// get the VA for the array of name pointers
		dwNameArray = ( dwLibraryAddress + pExportDirectory->AddressOfNames );
				
		// get the VA for the array of name ordinals
		dwNameOrdinals = ( dwLibraryAddress + pExportDirectory->AddressOfNameOrdinals );

		// test if we are importing by name or by ordinal...
		if( ((DWORD)lpProcName & 0xFFFF0000 ) == 0x00000000 )
		{
			// import by ordinal...

			// use the import ordinal (- export ordinal base) as an index into the array of addresses
			dwAddressArray += ( ( IMAGE_ORDINAL32( (DWORD)lpProcName ) - pExportDirectory->Base ) * sizeof(DWORD) );

			// resolve the address for this imported function
			fpResult = (FARPROC)( dwLibraryAddress + DEREF_32(dwAddressArray) );
		}
		else
		{
			// import by name...
			DWORD dwCounter = pExportDirectory->NumberOfNames;
			while( dwCounter-- )
			{
				char * cpExportedFunctionName = (char *)(dwLibraryAddress + DEREF_32( dwNameArray ));
				
				// test if we have a match...
				if( strcmp( cpExportedFunctionName, lpProcName ) == 0 )
				{
					// use the functions name ordinal as an index into the array of name pointers
					dwAddressArray += ( DEREF_16( dwNameOrdinals ) * sizeof(DWORD) );
					
					// calculate the virtual address for the function
					fpResult = (FARPROC)(dwLibraryAddress + DEREF_32( dwAddressArray ));
					
					// finish...
					break;
				}
						
				// get the next exported function name
				dwNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				dwNameOrdinals += sizeof(WORD);
			}
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		fpResult = NULL;
	}

	return fpResult;
}
//===============================================================================================//