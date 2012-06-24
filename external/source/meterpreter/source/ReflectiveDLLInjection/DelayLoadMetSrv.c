//===============================================================================================//
// Copyright (c) 2009, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
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
#include "DelayLoadMetSrv.h"
#include "GetProcAddressR.h"

// The handle to the injected metsrv.dll, needed for delay loading...
HMODULE hMetSrv = NULL; 

// All server extensions must support delay loading of metsrv.dll because this dll can be injected
// via reflective dll injection, as such normal calls to LoadLibrary/GetModuleHandle/GetProcAddress
// to resolve exports in metsrv.dll will not work as metsrv.dll will be 'invisible' to the native 
// windows kernel32 api's. Theirfore we delay load metsrv.dll and intercept loading and resolving of
// its exports and resolve them using our own GetProcAddressR() function.
// 
// To enable all of this in a new extnesion:
// 1. Add metsrv.dll to the DELAYLOAD option in the projects properties (Configuration->Linker->Input).
// 2. Add in the include file #include "DelayLoadMetSrv.h".
// 3. Add the macro "EnableDelayLoadMetSrv();" after all your includes.
// 4. Add the line "hMetSrv = remote->hMetSrv;" in your InitServerExtension() function.

//===============================================================================================//




FARPROC WINAPI delayHook( unsigned dliNotify, PDelayLoadInfo pdli )
{
	switch( dliNotify )
	{
		case dliNotePreLoadLibrary:
			// If we are trying to delay load metsrv.dll we can just return the
			// HMODULE of the injected metsrv library (set in InitServerExtension).
			if( strcmp( pdli->szDll, "metsrv.dll" ) == 0 );
				return (FARPROC)hMetSrv;
			break;
		case dliNotePreGetProcAddress:
			// If we are trying to get the address of an exported function in the
			// metsrv.dll we must use GetProcAddressR() in case the metsrv was loaded
			// via reflective dll injection
			if( strcmp( pdli->szDll, "metsrv.dll" ) == 0 )
				return GetProcAddressR( pdli->hmodCur, pdli->dlp.szProcName );
			break;
		default:
			return NULL;
	}

	return NULL;
}
//===============================================================================================//