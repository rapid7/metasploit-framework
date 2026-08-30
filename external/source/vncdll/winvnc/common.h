#ifndef _COMMON_H
#define _COMMON_H

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

//#define DEBUGTRACE

#ifdef DEBUGTRACE
#include <stdlib.h>
#define dprintf(...) real_dprintf(__VA_ARGS__)
#ifndef DPRINTF
#define DPRINTF
static void real_dprintf(char *format, ...) {
	va_list args;
	char buffer[1024];
	FILE * fp = fopen("c:\\debug_log_vncdll.txt","a");
	va_start(args,format);
	vsnprintf_s(buffer, sizeof(buffer), sizeof(buffer)-3, format,args);
	strcat_s(buffer, sizeof(buffer), "\r\n\x00");
	if(fp)
	{
		fputs( buffer, fp );
		fclose(fp);
	}
	OutputDebugString(buffer);
}
#endif
#else
#define dprintf(...) do{}while(0);
#endif

// Simple macro to close a handle and set the handle to NULL.
#define CLOSE_HANDLE( h )	if( h ) { CloseHandle( h ); h = NULL; }

#define BREAK_ON_ERROR( str ) { dwResult = GetLastError(); dprintf( "%s. error=%d", str, dwResult ); break; }
#define BREAK_WITH_ERROR( str, err ) { dwResult = err; dprintf( "%s. error=%d", str, dwResult ); break; }
#define BREAK_ON_WSAERROR( str ) { dwResult = WSAGetLastError(); dprintf( "%s. error=%d", str, dwResult ); break; }

typedef struct _PIXELFORMAT
{
    BYTE bpp;
    BYTE depth;
    BYTE bigendian;
    BYTE truecolour;
    WORD redmax;
    WORD greenmax;
    WORD bluemax;
    BYTE redshift;
    BYTE greenshift;
    BYTE blueshift;
    BYTE pad1;
    WORD pad2;
} PIXELFORMAT;

/*typedef struct _DICTMSG
{
	DWORD dwId;
	DWORD dwDictLength;
	BYTE bDictBuffer[1];
} DICTMSG;*/

/*
 * The context used for the agent to keep the vnc stream back to the client consistent during session switching.
 */
typedef struct _AGENT_CTX
{
	// The WSAPROTOCOL_INFO structure for the socket back to the client.
	WSAPROTOCOL_INFO info;
	// Flag to disable the creation of a courtesy shell on the input desktop.
	BOOL bDisableCourtesyShell;
	// The event to terminate the vnc agent.
	HANDLE hCloseEvent;
	// A flag to force only the first agent instance to perform the RFB initilization.
	BOOL bInit;
	// The encoding used by the last agent, we can then force the next agent to keep using
	// the last known encoding in order to keep the remote client's RFB stream consistent.
	DWORD dwEncoding;
	// A hex value used for the loaders pipe server
	DWORD dwPipeName;
	// The rfb streams current pixel format.
	PIXELFORMAT PixelFormat;
	// Various settings for the rfb stream.
	DWORD dwCompressLevel;
	DWORD dwQualityLevel;
	BOOL bUseCopyRect;
	BOOL bEncodingRichCursor;
	BOOL bEncodingPointerPos;
	BOOL bEncodingLastRect;
	BOOL bEncodingNewfbSize;
	BOOL bEncodingXCursor;
	//DICTMSG * dictionaries[4];
} AGENT_CTX, * LPAGENT_CTX;

#define MESSAGE_SETENCODING					0x28471649
#define MESSAGE_SETPIXELFORMAT				0x92785926
#define MESSAGE_SETCOMPRESSLEVEL			0x82658926
#define MESSAGE_SETQUALITYLEVEL				0x31857295
#define MESSAGE_SETCOPYRECTUSE				0x91748275
#define MESSAGE_SETENCODINGRICHCURSOR		0x39185037
#define MESSAGE_SETENCODINGPOINTERPOS		0x47295620
#define MESSAGE_SETENCODINGLASTRECT			0x11984659
#define MESSAGE_SETENCODINGNEWFBSIZE		0x94856345
#define MESSAGE_SETENCODINGXCURSOR			0x81659265
#define MESSAGE_SETZLIBDICTIONARY			0x91601668

#endif