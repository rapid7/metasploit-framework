#pragma once

#include <stdio.h>
#include <tchar.h>

#include <string>

#include <windows.h>

//
//	By Pavel

//
//	Defines names of pipes that can be accessed by name for redirecting IO.
//
const extern TCHAR *STDIn_PIPE;
const extern TCHAR *STDOut_PIPE;
const extern TCHAR *STDErr_PIPE;

//
//	Structure that is passed to newly created thread.
//	Defines how to redirect IO
//
typedef struct _TRedirectorPair {
	HANDLE Source;
	HANDLE Destination;
	//
	//	Uses directly Console IO instead of ReadFile and WriteFile
	//
	bool DestinationConsole;
	HANDLE Thread;
	//
	//	If true, prevent thread's exit on any IO error.
	//
	bool KeepAlive;
	std::wstring Name;
	//
	//	Appends 0x0A which is the one line terminator for linux with 0x0D. ( \r \n escapes)
	//
	bool Linux;
}TRedirectorPair;

DWORD WINAPI Redirector( LPVOID Parameter );

