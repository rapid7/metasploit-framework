#include "precomp.h"

/*
 * Shutdowns, restarts, etc the remote machine.  Calls ExitWindowsEx
 *
 * TLVs:
 *
 * req: TLV_TYPE_POWER_FLAGS   - Flags to ExitWindowsEx
 * req: TLV_TYPE_POWER_REASON  - Shutdown reason
 */
DWORD request_sys_power_exitwindows(Remote * remote, Packet * packet)
{
	Packet * response = packet_create_response(packet);

	HANDLE           token = NULL;
	TOKEN_PRIVILEGES tkp;

	DWORD result = ERROR_SUCCESS;
	DWORD flags  = packet_get_tlv_value_uint(packet, TLV_TYPE_POWER_FLAGS);
	DWORD reason = packet_get_tlv_value_uint(packet, TLV_TYPE_POWER_REASON);

// 		result = ERROR_INVALID_PARAMETER;

	do {
		if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) == 0) {
			result = GetLastError();
			break;
		}

		if(LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid) == 0) {
			result = GetLastError();
			break;
		}

		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if(AdjustTokenPrivileges(token, FALSE, &tkp, 0, NULL, NULL) == 0) {
			result = GetLastError();
			break;
		}

		if(ExitWindowsEx(flags, reason) == 0) {
			result = GetLastError();
			break;
		}
	} while(0);

	packet_transmit_response(result, remote, response);

	if(token)
		CloseHandle(token);

	return ERROR_SUCCESS;
}