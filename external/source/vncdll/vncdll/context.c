#include "loader.h"
#include "context.h"

AGENT_CTX AgentContext = {0};

/*
 *
 */
VOID context_init( VOID )
{
	memset( &AgentContext, 0, sizeof(AGENT_CTX) );

	AgentContext.bDisableCourtesyShell = FALSE;
	AgentContext.bInit                 = TRUE;
	AgentContext.hCloseEvent           = NULL;
	AgentContext.dwEncoding            = 0;
	AgentContext.dwCompressLevel       = 6;
	AgentContext.dwQualityLevel        = -1;
	AgentContext.bUseCopyRect          = FALSE;
	AgentContext.bEncodingRichCursor   = FALSE;
	AgentContext.bEncodingPointerPos   = FALSE;
	AgentContext.bEncodingLastRect     = FALSE;
	AgentContext.bEncodingNewfbSize    = FALSE;
	AgentContext.bEncodingXCursor      = FALSE;

	/*AgentContext.dictionaries[0]       = NULL;
	AgentContext.dictionaries[1]       = NULL;
	AgentContext.dictionaries[2]       = NULL;
	AgentContext.dictionaries[3]       = NULL;*/

	AgentContext.dwPipeName            = ( GetTickCount() ^ (DWORD)&AgentContext );
}

/*
 * Try to read an exact ammount of data from a pipe and return 
 * when either the data has been read or a failure occurs.
 */
DWORD _readexact( HANDLE hPipe, DWORD dwLength, BYTE * pBuffer )
{
	DWORD dwTotal = 0;
	DWORD dwRead  = 0;

	do
	{
		while( dwTotal < dwLength )
		{
			if( !PeekNamedPipe( hPipe, NULL, 0, NULL, &dwRead, NULL ) )
				break;

			if( !dwRead )
			{
				Sleep( 50 );
				continue;
			}

			if( ReadFile( hPipe, (LPVOID)((LPBYTE)pBuffer + dwTotal), (dwLength - dwTotal), &dwRead, NULL ) )
				dwTotal += dwRead;
		}

	} while( 0 );

	return dwTotal;
}

/*
 * A thread to pick up any messages being posted back to the loader (such as an encoder change in the stream)
 */
DWORD WINAPI context_message_thread( LPVOID lpParameter )
{
	DWORD dwResult            = ERROR_SUCCESS;
	HANDLE hServerPipe        = NULL;
	BYTE * pBuffer            = NULL;
	char cNamedPipe[MAX_PATH] = {0};

	__try
	{
		do
		{
			_snprintf_s( cNamedPipe, MAX_PATH, MAX_PATH - 1, "\\\\.\\pipe\\%08X", AgentContext.dwPipeName );

			dprintf("[LOADER] loader_message_thread. cNamedPipe=%s", cNamedPipe );
				
			hServerPipe = CreateNamedPipe( cNamedPipe, PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0, 0, 0, NULL );
			if( !hServerPipe )
				BREAK_ON_ERROR( "[LOADER] loader_message_thread. CreateNamedPipe failed" );
				
			while( TRUE )
			{
				struct _hdr {
					DWORD dwMessage;
					DWORD dwLength;
				} header = {0};
				DWORD dwTotal = 0;

				if( !ConnectNamedPipe( hServerPipe, NULL ) )
				{
					if( GetLastError() != ERROR_PIPE_CONNECTED )
						continue;
				}

				dwTotal = _readexact( hServerPipe, 8, (BYTE *)&header );
				if( dwTotal != sizeof( struct _hdr ) )
					BREAK_WITH_ERROR( "[LOADER] loader_message_thread. _readexact header failed", ERROR_INVALID_HANDLE );

				pBuffer = (BYTE *)malloc( header.dwLength );
				if( !pBuffer )
					BREAK_WITH_ERROR( "[LOADER] loader_message_thread. pBuffer malloc failed", ERROR_INVALID_HANDLE );
				
				dwTotal = _readexact( hServerPipe, header.dwLength, pBuffer );
				if( dwTotal != header.dwLength )
					BREAK_WITH_ERROR( "[LOADER] loader_message_thread. _readexact pBuffer failed", ERROR_INVALID_HANDLE );

				DisconnectNamedPipe( hServerPipe );

				switch( header.dwMessage )
				{
					case MESSAGE_SETENCODING:
						if( header.dwLength != sizeof(DWORD) )
						{
							dprintf("[LOADER] loader_message_thread. MESSAGE_SETENCODING, not enought data (got %d bytes)", header.dwLength );
							break;
						}
						AgentContext.dwEncoding = *(DWORD *)pBuffer;
						dprintf("[LOADER] loader_message_thread. MESSAGE_SETENCODING, new encoding is %d", AgentContext.dwEncoding );
						break;
					case MESSAGE_SETPIXELFORMAT:
						if( header.dwLength != sizeof(PIXELFORMAT) )
						{
							dprintf("[LOADER] loader_message_thread. MESSAGE_SETPIXELFORMAT, not enought data (got %d bytes)", header.dwLength );
							break;
						}
						memcpy( &AgentContext.PixelFormat, pBuffer, sizeof(PIXELFORMAT) );
						dprintf("[LOADER] loader_message_thread. MESSAGE_SETPIXELFORMAT" );
						break;
					case MESSAGE_SETCOMPRESSLEVEL:
						if( header.dwLength != sizeof(DWORD) )
						{
							dprintf("[LOADER] loader_message_thread. MESSAGE_SETCOMPRESSLEVEL, not enought data (got %d bytes)", header.dwLength );
							break;
						}
						AgentContext.dwCompressLevel = *(DWORD *)pBuffer;
						dprintf("[LOADER] loader_message_thread. MESSAGE_SETCOMPRESSLEVEL, new compress level is %d", AgentContext.dwCompressLevel );
						break;
					case MESSAGE_SETQUALITYLEVEL:
						if( header.dwLength != sizeof(DWORD) )
						{
							dprintf("[LOADER] loader_message_thread. MESSAGE_SETQUALITYLEVEL, not enought data (got %d bytes)", header.dwLength );
							break;
						}
						AgentContext.dwQualityLevel = *(DWORD *)pBuffer;
						dprintf("[LOADER] loader_message_thread. MESSAGE_SETQUALITYLEVEL, new quality level is %d", AgentContext.dwQualityLevel );
						break;
					case MESSAGE_SETCOPYRECTUSE:
						if( header.dwLength != sizeof(BOOL) )
						{
							dprintf("[LOADER] loader_message_thread. MESSAGE_SETCOPYRECTUSE, not enought data (got %d bytes)", header.dwLength );
							break;
						}
						AgentContext.bUseCopyRect = *(BOOL *)pBuffer;
						dprintf("[LOADER] loader_message_thread. MESSAGE_SETCOPYRECTUSE, new bUseCopyRect is %d", AgentContext.bUseCopyRect );
						break;
					case MESSAGE_SETENCODINGRICHCURSOR:
						if( header.dwLength != sizeof(BOOL) )
						{
							dprintf("[LOADER] loader_message_thread. MESSAGE_SETENCODINGRICHCURSOR, not enought data (got %d bytes)", header.dwLength );
							break;
						}
						AgentContext.bEncodingRichCursor = *(BOOL *)pBuffer;
						dprintf("[LOADER] loader_message_thread. MESSAGE_SETENCODINGRICHCURSOR, new dwEncodingRichCursor is %d", AgentContext.bEncodingRichCursor );
						break;
					case MESSAGE_SETENCODINGPOINTERPOS:
						if( header.dwLength != sizeof(BOOL) )
						{
							dprintf("[LOADER] loader_message_thread. MESSAGE_SETENCODINGPOINTERPOS, not enought data (got %d bytes)", header.dwLength );
							break;
						}
						AgentContext.bEncodingPointerPos = *(BOOL *)pBuffer;
						dprintf("[LOADER] loader_message_thread. MESSAGE_SETENCODINGPOINTERPOS, new dwEncodingPointerPos is %d", AgentContext.bEncodingPointerPos );
						break;
					case MESSAGE_SETENCODINGLASTRECT:
						if( header.dwLength != sizeof(BOOL) )
						{
							dprintf("[LOADER] loader_message_thread. MESSAGE_SETENCODINGLASTRECT, not enought data (got %d bytes)", header.dwLength );
							break;
						}
						AgentContext.bEncodingLastRect = *(BOOL *)pBuffer;
						dprintf("[LOADER] loader_message_thread. MESSAGE_SETENCODINGLASTRECT, new dwEncodingLastRect is %d", AgentContext.bEncodingLastRect );
						break;
					case MESSAGE_SETENCODINGNEWFBSIZE:
						if( header.dwLength != sizeof(BOOL) )
						{
							dprintf("[LOADER] loader_message_thread. MESSAGE_SETENCODINGNEWFBSIZE, not enought data (got %d bytes)", header.dwLength );
							break;
						}
						AgentContext.bEncodingNewfbSize = *(BOOL *)pBuffer;
						dprintf("[LOADER] loader_message_thread. MESSAGE_SETENCODINGNEWFBSIZE, new bEncodingNewfbSize is %d", AgentContext.bEncodingNewfbSize );
						break;
					case MESSAGE_SETENCODINGXCURSOR:
						if( header.dwLength != sizeof(BOOL) )
						{
							dprintf("[LOADER] loader_message_thread. MESSAGE_SETENCODINGXCURSOR, not enought data (got %d bytes)", header.dwLength );
							break;
						}
						AgentContext.bEncodingXCursor = *(BOOL *)pBuffer;
						dprintf("[LOADER] loader_message_thread. MESSAGE_SETENCODINGXCURSOR, new bEncodingXCursor is %d", AgentContext.bEncodingXCursor );
						break;
					/*
					case MESSAGE_SETZLIBDICTIONARY:
						if( header.dwLength < sizeof(DICTMSG) )
						{
							dprintf("[LOADER] loader_message_thread. MESSAGE_SETZLIBDICTIONARY, not enought data (got %d bytes)", header.dwLength );
							break;
						}
						else
						{
							DICTMSG * dmsg = (DICTMSG *)pBuffer;
							if( dmsg->dwId > 4 )
							{
								dprintf("[LOADER] loader_message_thread. MESSAGE_SETZLIBDICTIONARY, invalid id (got %d)", dmsg->dwId );
								break;
							}

							if( AgentContext.dictionaries[dmsg->dwId] )
								free( AgentContext.dictionaries[dmsg->dwId] );

							AgentContext.dictionaries[dmsg->dwId] = (DICTMSG *)malloc( sizeof(DICTMSG) + dmsg->dwDictLength );
							if( !AgentContext.dictionaries[dmsg->dwId] )
							{
								dprintf("[LOADER] loader_message_thread. MESSAGE_SETZLIBDICTIONARY, malloc failed" );
								break;
							}						
							
							AgentContext.dictionaries[dmsg->dwId]->dwId         = dmsg->dwId;
							AgentContext.dictionaries[dmsg->dwId]->dwDictLength = dmsg->dwDictLength;

							memcpy( &AgentContext.dictionaries[dmsg->dwId]->bDictBuffer, &dmsg->bDictBuffer, dmsg->dwDictLength );

							dprintf("[LOADER] loader_message_thread. MESSAGE_SETZLIBDICTIONARY, id=%d, length=%d", dmsg->dwId, dmsg->dwDictLength );
						}
						break;
					*/
					default:
						dprintf("[LOADER] loader_message_thread. Unknown message 0x%08X", header.dwMessage );
						break;
				}

				if( pBuffer )
				{
					free( pBuffer );
					pBuffer = NULL;
				}
			}

		} while( 0 );
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		dprintf( "[LOADER] loader_message_thread. EXCEPTION_EXECUTE_HANDLER\n\n" );
	}

	dprintf("[LOADER] loader_message_thread. thread finishing...");

	if( hServerPipe )
	{
		DisconnectNamedPipe( hServerPipe );
		CLOSE_HANDLE( hServerPipe );
	}

	if( pBuffer )
		free( pBuffer );

	return dwResult;
}
