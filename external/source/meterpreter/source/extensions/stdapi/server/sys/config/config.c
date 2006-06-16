#include "precomp.h"

/*
 * sys_getuid
 * ----------
 *
 * Gets the user information of the user the server is executing as
 */
DWORD request_sys_config_getuid(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	CHAR username[512];
	DWORD size = sizeof(username);

	memset(username, 0, sizeof(username));

	do
	{
		// Get the username
		if (!GetUserName(username, &size))
		{
			res = GetLastError();
			break;
		}

		packet_add_tlv_string(response, TLV_TYPE_USER_NAME, username);

	} while (0);

	// Transmit the response
	packet_transmit_response(res, remote, response);

	return res;
}

/*
 * sys_sysinfo
 * ----------
 *
 * Get system information such as computer name and OS version
 */
DWORD request_sys_config_sysinfo(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	CHAR computer[512], buf[512], *osName = NULL;
	DWORD res = ERROR_SUCCESS;
	DWORD size = sizeof(computer);
	OSVERSIONINFO v;

	memset(&v, 0, sizeof(v));
	memset(computer, 0, sizeof(computer));
	memset(buf, 0, sizeof(buf));

	v.dwOSVersionInfoSize = sizeof(v);

	do
	{
		// Get the computer name
		if (!GetComputerName(computer, &size))
		{
			res = GetLastError();
			break;
		}

		packet_add_tlv_string(response, TLV_TYPE_COMPUTER_NAME, computer);

		// Get the operating system version information
		if (!GetVersionEx(&v))
		{
			res = GetLastError();
			break;
		}

		if (v.dwMajorVersion == 3)
			osName = "Windows NT 3.51";
		else if (v.dwMajorVersion == 4)
		{
			if (v.dwMinorVersion == 0 && v.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
				osName = "Windows 95";
			else if (v.dwMinorVersion == 10)
				osName = "Windows 98";
			else if (v.dwMinorVersion == 90)
				osName = "Windows ME";
			else if (v.dwMinorVersion == 0 && v.dwPlatformId == VER_PLATFORM_WIN32_NT)
				osName = "Windows NT 4.0";
		}
		else 
		{
			if (v.dwMinorVersion == 0)
				osName = "Windows 2000";
			else if (v.dwMinorVersion == 1)
				osName = "Windows XP";
			else if (v.dwMinorVersion == 2)
				osName = "Windows .NET Server";
		}
		
		if (!osName)
			osName = "Unknown";

		_snprintf(buf, sizeof(buf) - 1, "%s (Build %lu, %s).", osName, 
				v.dwBuildNumber, v.szCSDVersion);

		packet_add_tlv_string(response, TLV_TYPE_OS_NAME, buf);

	} while (0);

	// Transmit the response
	packet_transmit_response(res, remote, response);

	return res;
}

/*
 * sys_config_rev2self
 *
 * Calls RevertToSelf()
 */
DWORD request_sys_config_rev2self(Remote *remote, Packet *packet)
{
	RevertToSelf();

	packet_transmit_empty_response(remote, packet, GetLastError());

	return ERROR_SUCCESS;
}
