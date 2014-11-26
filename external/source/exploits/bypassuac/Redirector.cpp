#include "stdafx.h"

#include "CMMN.h"
#include "Redirector.h"
#include <windows.h>

const TCHAR *STDIn_PIPE   = TEXT("\\\\.\\pipe\\TIOR_In");
const TCHAR *STDOut_PIPE  = TEXT("\\\\.\\pipe\\TIOR_Out");
const TCHAR *STDErr_PIPE  = TEXT("\\\\.\\pipe\\TIOR_Err");

DWORD WINAPI Redirector( LPVOID Parameter )
{
	assert( Parameter );
	TRedirectorPair *pair = reinterpret_cast<TRedirectorPair*>( Parameter );

	CHAR read_buff[2];
	DWORD nBytesRead,nBytesWrote;

	bool was_0d = false;
	bool error = false;
	while ( ! error )
	{
		if( ! ReadFile( pair->Source, read_buff, 1, &nBytesRead, NULL) )
		{
			
			error = true && (!pair->KeepAlive);
			break;
		}

		if ( pair->Linux )
		{
			if ( ! was_0d )
			{
				if ( read_buff[0] == 0xa )
				{
					read_buff[0] = 0xd;
					read_buff[1] = 0xa;
					nBytesRead = 2;
				}
			} 
			was_0d = read_buff[nBytesRead - 1]  == 0x0d;
		}

		for ( DWORD i = 0; i < nBytesRead; i++ )
		{
			if ( pair->DestinationConsole )
			{
				//
				//	Emulate console input.
				//

				INPUT_RECORD inp = {0};
				inp.EventType = KEY_EVENT;
				inp.Event.KeyEvent.uChar.AsciiChar = read_buff[i];
				inp.Event.KeyEvent.wRepeatCount = 1;
				inp.Event.KeyEvent.wVirtualKeyCode = 0;
				inp.Event.KeyEvent.wVirtualScanCode = 0;
				inp.Event.KeyEvent.bKeyDown = TRUE;
				inp.Event.KeyEvent.dwControlKeyState = 0;

				if ( ! WriteConsoleInput( pair->Destination, &inp, 1, &nBytesWrote) )
				{
					error = true && (!pair->KeepAlive);
					break;
				}
			}
			else
			{
				if ( ! WriteFile( pair->Destination, &read_buff[i], 1, &nBytesWrote, NULL) )
				{
					error = true && (!pair->KeepAlive);
					break;
				}
			}
		}
	}

	return EXIT_SUCCESS;
}

