#include "precomp.h"

extern HMODULE hookLibrary;

/*
 * Enables or disables keyboard input
 */
DWORD request_ui_enable_keyboard(Remote *remote, Packet *request)
{
	Packet *response = packet_create_response(request);
	BOOLEAN enable = FALSE;
	DWORD result = ERROR_SUCCESS;

	enable = packet_get_tlv_value_bool(request, TLV_TYPE_BOOL);

	// If there's no hook library loaded yet
	if (!hookLibrary)
		extract_hook_library();

	// If the hook library is loaded successfully...
	if (hookLibrary)
	{
		DWORD (*enableKeyboardInput)(BOOL enable) = (DWORD (*)(BOOL))GetProcAddress(
				hookLibrary, "enable_keyboard_input");

		if (enableKeyboardInput)
			result = enableKeyboardInput(enable);
	}
	else
		result = GetLastError();

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}
