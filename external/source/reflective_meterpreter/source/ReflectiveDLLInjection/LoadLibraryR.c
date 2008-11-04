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
//#include <stdio.h>
//#include <string.h>
#include "LoadLibraryR.h"
//===============================================================================================//
DWORD Rva2Offset( DWORD dwRva, DWORD dwBaseAddress )
{    
    DWORD dwExportDir = 0;
	DWORD dwTotalSections = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD dwIndex = 0;
	PIMAGE_NT_HEADERS32 pNtHeaders = NULL;
	
	pNtHeaders = (PIMAGE_NT_HEADERS32)(dwBaseAddress + ((PIMAGE_DOS_HEADER)dwBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	dwTotalSections = pNtHeaders->FileHeader.NumberOfSections;

    if( dwRva < pSectionHeader[0].PointerToRawData )
        return dwRva;

    for( dwIndex=0 ; dwIndex<dwTotalSections ; dwIndex++ )
    {   
        if(dwRva >= pSectionHeader[dwIndex].VirtualAddress && dwRva < pSectionHeader[dwIndex].VirtualAddress + pSectionHeader[dwIndex].SizeOfRawData )           
           return ( dwRva - pSectionHeader[dwIndex].VirtualAddress + pSectionHeader[dwIndex].PointerToRawData );
    }
    
    return 0;
}
//===============================================================================================//
DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer )
{
	DWORD dwBaseAddress   = 0;
	DWORD dwExportDir     = 0;
	DWORD dwNameArray     = 0;
	DWORD dwAddressArray  = 0;
	DWORD dwNameOrdinals  = 0;
	DWORD dwCounter       = 0;

	dwBaseAddress = (DWORD)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	dwExportDir = dwBaseAddress + ((PIMAGE_DOS_HEADER)dwBaseAddress)->e_lfanew;

	// dwNameArray = the address of the modules export directory entry
	dwNameArray = (DWORD)&((PIMAGE_NT_HEADERS32)dwExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	// get the File Offset of the export directory
	dwExportDir = ((PIMAGE_DATA_DIRECTORY)dwNameArray)->VirtualAddress;
	dwExportDir = dwBaseAddress + Rva2Offset( dwExportDir, dwBaseAddress );

	// get the File Offset for the array of name pointers
	dwNameArray = ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->AddressOfNames;
	dwNameArray = dwBaseAddress + Rva2Offset( dwNameArray, dwBaseAddress );

	// get the File Offset for the array of addresses
	dwAddressArray = ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->AddressOfFunctions;
	dwAddressArray = dwBaseAddress + Rva2Offset( dwAddressArray, dwBaseAddress );

	// get the File Offset for the array of name ordinals
	dwNameOrdinals = ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->AddressOfNameOrdinals;
	dwNameOrdinals = dwBaseAddress + Rva2Offset( dwNameOrdinals, dwBaseAddress );	

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while( dwCounter-- )
	{
		char * cpExportedFunctionName = (char *)(dwBaseAddress + Rva2Offset( DEREF_32( dwNameArray ), dwBaseAddress ));

		if( strstr( cpExportedFunctionName, "ReflectiveLoader" ) != NULL )
		{
			// get the File Offset for the array of addresses
			dwAddressArray = ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->AddressOfFunctions;
			dwAddressArray = dwBaseAddress + Rva2Offset( dwAddressArray, dwBaseAddress );	
	
			// use the functions name ordinal as an index into the array of name pointers
			dwAddressArray += ( DEREF_16( dwNameOrdinals ) * sizeof(DWORD) );

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset( DEREF_32( dwAddressArray ), dwBaseAddress );
		}
		// get the next exported function name
		dwNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		dwNameOrdinals += sizeof(WORD);
	}

	return 0;
}
//===============================================================================================//
// Loads a DLL image from memory via its exported ReflectiveLoader function
HMODULE WINAPI LoadLibraryR( LPVOID lpBuffer, DWORD dwLength )
{
	HMODULE hResult                    = NULL;
	DWORD dwReflectiveLoaderOffset     = 0;
	DWORD dwOldProtect1                = 0;
	DWORD dwOldProtect2                = 0;
	REFLECTIVELOADER pReflectiveLoader = NULL;
	DLLMAIN pDllMain                   = NULL;

	if( lpBuffer == NULL || dwLength == 0 )
		return NULL;

	__try
	{
		// check if the library has a ReflectiveLoader...
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpBuffer );
		if( dwReflectiveLoaderOffset != 0 )
		{
			pReflectiveLoader = (REFLECTIVELOADER)((DWORD)lpBuffer + dwReflectiveLoaderOffset);

			// we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
			// this assumes lpBuffer is the base address of the region of pages and dwLength the size of the region
			if( VirtualProtect( lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1 ) )
			{
				// call the librarys ReflectiveLoader...
				pDllMain = (DLLMAIN)pReflectiveLoader();
				if( pDllMain != NULL )
				{
					// call the loaded librarys DllMain to get its HMODULE
					// Dont call DLL_METASPLOIT_ATTACH/DLL_METASPLOIT_DETACH as that is for payloads only.
					if( !pDllMain( NULL, DLL_QUERY_HMODULE, &hResult ) )	
						hResult = NULL;
				}

				// revert to the previous protection flags...
				VirtualProtect( lpBuffer, dwLength, dwOldProtect1, &dwOldProtect2 );
			}
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		hResult = NULL;
	}

	return hResult;
}
//===============================================================================================//
// Loads a DLL image from memory into the address space of a host process via the dll's exported ReflectiveLoader function
/*
BOOL WINAPI LoadRemoteLibraryR( HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength )
{
	BOOL bResult                              = FALSE;
	DWORD dwReflectiveLoaderOffset            = 0;
	LPVOID lpRemoteLibraryBuffer              = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;

	if( hProcess == NULL || lpBuffer == NULL || dwLength == 0 )
		return FALSE;

	__try
	{
		// check if the library has a ReflectiveLoader...
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpBuffer );
		if( dwReflectiveLoaderOffset != 0 )
		{
			// alloc memory (RWX) in the host process for the dll...
			lpRemoteLibraryBuffer = (LPVOID)VirtualAllocEx( hProcess, NULL, dwLength, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE ); 
			if( lpRemoteLibraryBuffer == NULL )
				return FALSE; 

			// write the dll's image into the host process...
			if( WriteProcessMemory( hProcess, (LPVOID)lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL ) == 0 )
				return FALSE; 

			// add the offset to ReflectiveLoader() to the remote library address...
			lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((DWORD)lpRemoteLibraryBuffer + (DWORD)dwReflectiveLoaderOffset);

			// create a remote thread in the host process to call the ReflectiveLoader!
			// TO-DO: fix the difference between the funk defs of ReflectiveLoader(VOID) and ThreadRoutine(LPVOID lpParam)
			if( CreateRemoteThread( hProcess, NULL, (SIZE_T)NULL, lpReflectiveLoader, NULL, (DWORD)NULL, NULL ) == NULL )
				return FALSE;

			bResult = TRUE;
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		bResult = FALSE;
	}
 
	return bResult;
}
*/
//===============================================================================================//
