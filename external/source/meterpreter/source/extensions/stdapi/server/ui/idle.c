#include "precomp.h"

typedef struct tagLASTINPUTINFO {
    UINT cbSize;
    DWORD dwTime;
} LASTINPUTINFO, *PLASTINPUTINFO;

/*
 * Returns the number of seconds the local user has been idle
 */
DWORD request_ui_get_idle_time(Remote *remote, Packet *request)
{
	LASTINPUTINFO info;
	HMODULE user32 = NULL;
	Packet *response = packet_create_response(request);
	DWORD result = ERROR_SUCCESS;
	BOOL (WINAPI *getLastInputInfo)(PLASTINPUTINFO) = NULL;

	do
	{
		// Load user32
		if (!(user32 = LoadLibrary("user32")))
		{
			result = GetLastError();
			break;
		}

		// Resolve the address of GetLastInputInfo (Windows 2000+)
		if (!(getLastInputInfo = (BOOL (WINAPI *)(PLASTINPUTINFO))GetProcAddress(
				user32, "GetLastInputInfo")))
		{
			result = GetLastError();
			break;
		}

		info.cbSize = sizeof(info);

		if (getLastInputInfo(&info))
			packet_add_tlv_uint(response, TLV_TYPE_IDLE_TIME,
					(GetTickCount() - info.dwTime) / 1000);
		else
			result = GetLastError();

	} while (0);

	// Unload the library
	if (user32)
		FreeLibrary(user32);

	// Transmit the response packet
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}
