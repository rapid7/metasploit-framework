// Copyright (C) 2006-2010, Rapid7, Inc
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright notice,
//       this list of conditions and the following disclaimer in the documentation
//       and/or other materials provided with the distribution.
//
//     * Neither the name of Rapid7, Inc nor the names of its contributors
//       may be used to endorse or promote products derived from this software
//       without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#ifndef _VNCDLL_LOADER_CONTEXT_H
#define _VNCDLL_LOADER_CONTEXT_H
//===============================================================================================//

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

//===============================================================================================//

VOID context_init( VOID );

DWORD WINAPI context_message_thread( LPVOID lpParameter );

//===============================================================================================//
#endif
//===============================================================================================//
