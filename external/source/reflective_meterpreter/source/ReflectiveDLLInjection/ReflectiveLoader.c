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
#include "ReflectiveLoader.h"
//===============================================================================================//
// you must implement this function...
extern DWORD DLLEXPORT Init( SOCKET socket );
//===============================================================================================//
// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;
//===============================================================================================//
// This is our position independent reflective Dll loader/injector
DLLEXPORT DWORD WINAPI ReflectiveLoader( VOID )
{
	// the functions we need
	LOADLIBRARYA pLoadLibraryA;
	GETPROCADDRESS pGetProcAddress;
	VIRTUALALLOC pVirtualAlloc;
	BYTE bCounter = 3;

	// the initial location of this image in memory
	DWORD dwLibraryAddress;
	// the kernels base address and later this images newly loaded base address
	DWORD dwBaseAddress;

	// variables for processing the kernels export table
	DWORD dwAddressArray;
	DWORD dwNameArray;
	DWORD dwExportDir;
	DWORD dwNameOrdinals;
	DWORD dwHashValue;

	// variables for loading this image
	DWORD dwHeaderValue;
	DWORD dwValueA;
	DWORD dwValueB;
	DWORD dwValueC;
	DWORD dwValueD;

	// STEP 0: calculate our images current base address

	// we will start searching backwards from our current EIP
	__asm call getip
	__asm getip: pop dwLibraryAddress

	// loop through memory backwards searching for our images base address
	// we dont need SEH style search as we shouldnt generate any access violations with this
	while( TRUE )
	{
		if( ((PIMAGE_DOS_HEADER)dwLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE )
		{
			dwHeaderValue = dwLibraryAddress + ((PIMAGE_DOS_HEADER)dwLibraryAddress)->e_lfanew;
			// break if we have found a valid MZ/PE header
			if( ((PIMAGE_NT_HEADERS32)dwHeaderValue)->Signature == IMAGE_NT_SIGNATURE )
				break;
		}
		dwLibraryAddress--;
	}

	// STEP 1: process the kernels exports for the functions our loader needs...

	// get the Process Enviroment Block
	dwBaseAddress = __get_peb();

	// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	dwBaseAddress = (DWORD)((_PPEB)dwBaseAddress)->pLdr;

	dwBaseAddress = DEREF_32( ((PPEB_LDR_DATA)dwBaseAddress)->InInitializationOrderModuleList.Flink );

	// get this kernels base address
	dwBaseAddress = DEREF_32( dwBaseAddress + 8 );

	// get the VA of the modules NT Header
	dwExportDir = dwBaseAddress + ((PIMAGE_DOS_HEADER)dwBaseAddress)->e_lfanew;

	// dwNameArray = the address of the modules export directory entry
	dwNameArray = (DWORD)&((PIMAGE_NT_HEADERS32)dwExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	// get the VA of the export directory
	dwExportDir = ( dwBaseAddress + ((PIMAGE_DATA_DIRECTORY)dwNameArray)->VirtualAddress );

	// get the VA for the array of name pointers
	dwNameArray = ( dwBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->AddressOfNames );
			
	// get the VA for the array of name ordinals
	dwNameOrdinals = ( dwBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->AddressOfNameOrdinals );

	// loop while we still have imports to find
	while( bCounter > 0 )
	{
		// compute the hash values for this function name
		dwHashValue = __hash( (char *)( dwBaseAddress + DEREF_32( dwNameArray ) )  );
				
		// if we have found a function we want we get its virtual address
		if( dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH || dwHashValue == VIRTUALALLOC_HASH )
		{
			// get the VA for the array of addresses
			dwAddressArray = ( dwBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->AddressOfFunctions );

			// use this functions name ordinal as an index into the array of name pointers
			dwAddressArray += ( DEREF_16( dwNameOrdinals ) * sizeof(DWORD) );

			// store this functions VA
			if( dwHashValue == LOADLIBRARYA_HASH )
				pLoadLibraryA = (LOADLIBRARYA)( dwBaseAddress + DEREF_32( dwAddressArray ) );
			else if( dwHashValue == GETPROCADDRESS_HASH )
				pGetProcAddress = (GETPROCADDRESS)( dwBaseAddress + DEREF_32( dwAddressArray ) );
			else if( dwHashValue == VIRTUALALLOC_HASH )
				pVirtualAlloc = (VIRTUALALLOC)( dwBaseAddress + DEREF_32( dwAddressArray ) );
			
			// decrement our counter
			bCounter--;
		}

		// get the next exported function name
		dwNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		dwNameOrdinals += sizeof(WORD);
	}

	// STEP 2: load our image into a new permanent location in memory...

	// get the VA of the NT Header for the PE to be loaded
	dwHeaderValue = dwLibraryAddress + ((PIMAGE_DOS_HEADER)dwLibraryAddress)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	dwBaseAddress = (DWORD)pVirtualAlloc( NULL, ((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	// we must now copy over the headers
	dwValueA = ((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader.SizeOfHeaders;
	dwValueB = dwLibraryAddress;
	dwValueC = dwBaseAddress;
	__memcpy( dwValueC, dwValueB, dwValueA );

	// STEP 3: load in all of our sections...

	// dwValueA = the VA of the first section
	dwValueA = ( (DWORD)&((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS32)dwHeaderValue)->FileHeader.SizeOfOptionalHeader );
	
	// itterate through all sections, loading them into memory.
	while( ((PIMAGE_NT_HEADERS32)dwHeaderValue)->FileHeader.NumberOfSections-- )
	{
		// dwValueB is the VA for this section
		dwValueB = ( dwBaseAddress + ((PIMAGE_SECTION_HEADER)dwValueA)->VirtualAddress );

		// dwValueC if the VA for this sections data
		dwValueC = ( dwLibraryAddress + ((PIMAGE_SECTION_HEADER)dwValueA)->PointerToRawData );

		// copy the section over
		dwValueD = ((PIMAGE_SECTION_HEADER)dwValueA)->SizeOfRawData;
		__memcpy( dwValueB, dwValueC, dwValueD );

		// get the VA of the next section
		dwValueA += sizeof( IMAGE_SECTION_HEADER );
	}

	// STEP 4: process our images import table...

	// dwValueB = the address of the import directory
	dwValueB = (DWORD)&((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	
	// we assume their is an import table to process
	// dwValueC is the first entry in the import table
	dwValueC = ( dwBaseAddress + ((PIMAGE_DATA_DIRECTORY)dwValueB)->VirtualAddress );
	
	// itterate through all imports
	while( ((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->Name )
	{
		// use LoadLibraryA to load the imported module into memory
		dwLibraryAddress = (DWORD)pLoadLibraryA( (LPCSTR)( dwBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->Name ) );

		// dwValueD = VA of the OriginalFirstThunk
		dwValueD = ( dwBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->OriginalFirstThunk );
	
		// dwValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		dwValueA = ( dwBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->FirstThunk );

		// itterate through all imported functions, importing by ordinal if no name present
		while( DEREF_32(dwValueA) )
		{
			// sanity check dwValueD as some compilers only import by FirstThunk
			if( dwValueD && ((PIMAGE_THUNK_DATA)dwValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG32 )
			{
				// get the VA of the modules NT Header
				dwExportDir = dwLibraryAddress + ((PIMAGE_DOS_HEADER)dwLibraryAddress)->e_lfanew;

				// dwNameArray = the address of the modules export directory entry
				dwNameArray = (DWORD)&((PIMAGE_NT_HEADERS32)dwExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

				// get the VA of the export directory
				dwExportDir = ( dwLibraryAddress + ((PIMAGE_DATA_DIRECTORY)dwNameArray)->VirtualAddress );

				// get the VA for the array of addresses
				dwAddressArray = ( dwLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->AddressOfFunctions );

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				dwAddressArray += ( ( IMAGE_ORDINAL32( ((PIMAGE_THUNK_DATA)dwValueD)->u1.Ordinal ) - ((PIMAGE_EXPORT_DIRECTORY )dwExportDir)->Base ) * sizeof(DWORD) );

				// patch in the address for this imported function
				DEREF_32(dwValueA) = ( dwLibraryAddress + DEREF_32(dwAddressArray) );
			}
			else
			{
				// get the VA of this functions import by name struct
				dwValueB = ( dwBaseAddress + DEREF_32(dwValueA) );

				// use GetProcAddress and patch in the address for this imported function
				DEREF_32(dwValueA) = (DWORD)pGetProcAddress( (HMODULE)dwLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)dwValueB)->Name );
			}
			// get the next imported function
			dwValueA += 4;
			if( dwValueD )
				dwValueD += 4;
		}

		// get the next import
		dwValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
	}

	// STEP 5: process all of our images relocations...

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	dwLibraryAddress = dwBaseAddress - ((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader.ImageBase;
	
	// dwValueB = the address of the relocation directory
	dwValueB = (DWORD)&((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

	// check if their are any relocations present
	if( ((PIMAGE_DATA_DIRECTORY)dwValueB)->Size )
	{
		// dwValueC is now the first entry (IMAGE_BASE_RELOCATION)
		dwValueC = ( dwBaseAddress + ((PIMAGE_DATA_DIRECTORY)dwValueB)->VirtualAddress );

		// and we itterate through all entries...
		while( ((PIMAGE_BASE_RELOCATION)dwValueC)->SizeOfBlock )
		{
			// dwValueA = the VA for this relocation block
			dwValueA = ( dwBaseAddress + ((PIMAGE_BASE_RELOCATION)dwValueC)->VirtualAddress );

			// dwValueB = number of entries in this relocation block
			dwValueB = ( ((PIMAGE_BASE_RELOCATION)dwValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof( IMAGE_RELOC );

			// dwValueD is now the first entry in the current relocation block
			dwValueD = dwValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while( dwValueB-- )
			{
                  // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required
				switch( ((PIMAGE_RELOC)dwValueD)->type )
				{
					case IMAGE_REL_BASED_HIGHLOW:
						*(DWORD *)(dwValueA + ((PIMAGE_RELOC)dwValueD)->offset) += dwLibraryAddress;
						break;
					case IMAGE_REL_BASED_HIGH:
						*(WORD *)(dwValueA + ((PIMAGE_RELOC)dwValueD)->offset) += HIWORD(dwLibraryAddress);
						break;
					case IMAGE_REL_BASED_LOW:
						*(WORD *)(dwValueA + ((PIMAGE_RELOC)dwValueD)->offset) += LOWORD(dwLibraryAddress);
						break;
					//case IMAGE_REL_BASED_HIGHADJ:
					//	break;
					default:
						break;
				}

				// get the next entry in the current relocation block
				dwValueD += sizeof( IMAGE_RELOC );
			}

			// get the next entry in the relocation directory
			dwValueC = dwValueC + ((PIMAGE_BASE_RELOCATION)dwValueC)->SizeOfBlock;
		}
	}

	// STEP 6: call our images entry point

	// dwValueA = the VA of our newly loaded DLL's entry point
	dwValueA = ( dwBaseAddress + ((PIMAGE_NT_HEADERS32)dwHeaderValue)->OptionalHeader.AddressOfEntryPoint );

	// call our DLLMain(), fudging our hinstDLL value
	((DLLMAIN)dwValueA)( (HINSTANCE)dwBaseAddress, DLL_PROCESS_ATTACH, NULL );

	// STEP 7: return our new DllMain address so whatever called us can call DLL_METASPLOIT_ATTACH/DLL_METASPLOIT_DETACH
	return (DWORD)dwValueA;
}
//===============================================================================================//
BOOL MetasploitDllAttach( SOCKET socket )
{
	Init( socket );
	return TRUE;
}
//===============================================================================================//
BOOL MetasploitDllDetach( DWORD dwExitFunc )
{
	switch( dwExitFunc )
	{
		case EXITFUNC_SEH:
			SetUnhandledExceptionFilter( NULL );
			break;
		case EXITFUNC_THREAD:
			ExitThread( 0 );
			break;
		case EXITFUNC_PROCESS:
			ExitProcess( 0 );
			break;
		default:
			break;
	}

	return TRUE;
}
//===============================================================================================//
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_METASPLOIT_ATTACH:
			bReturnValue = MetasploitDllAttach( (SOCKET)lpReserved );
			break;
		case DLL_METASPLOIT_DETACH:
			bReturnValue = MetasploitDllDetach( (DWORD)lpReserved );
			break;
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}
//===============================================================================================//