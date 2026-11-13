#include "meterpreter_micro.h"
#include "micro_runtime.h"
#include "micro_stdapi.h"

typedef DWORD(WINAPI* GetLogicalDriveStringsWFunction)(DWORD size, LPWSTR buffer);
typedef UINT(WINAPI* GetDriveTypeWFunction)(LPCWSTR root);
typedef BOOL(WINAPI* GetDiskFreeSpaceExWFunction)(LPCWSTR path, PULARGE_INTEGER available, PULARGE_INTEGER total, PULARGE_INTEGER free_bytes);
typedef DWORD(WINAPI* WNetGetUniversalNameWFunction)(LPCWSTR local_path, DWORD level, LPVOID buffer, LPDWORD size);

typedef struct _MicroUniversalName
{
	LPWSTR name;
} MicroUniversalName;

static MetApi* mount_api;

static DWORD mount_show(Remote* remote, Packet* packet)
{
	GetLogicalDriveStringsWFunction get_drives = (GetLogicalDriveStringsWFunction)micro_resolve(mount_api, "kernel32.dll", "GetLogicalDriveStringsW");
	GetDriveTypeWFunction get_type = (GetDriveTypeWFunction)micro_resolve(mount_api, "kernel32.dll", "GetDriveTypeW");
	GetDiskFreeSpaceExWFunction get_space = (GetDiskFreeSpaceExWFunction)micro_resolve(mount_api, "kernel32.dll", "GetDiskFreeSpaceExW");
	WNetGetUniversalNameWFunction get_universal = (WNetGetUniversalNameWFunction)micro_resolve(mount_api, "mpr.dll", "WNetGetUniversalNameW");
	Packet* response = mount_api->packet.create_response(packet);
	wchar_t drives[4 * 26 + 1];
	wchar_t* drive;
	DWORD result = ERROR_SUCCESS;
	micro_zero(drives, sizeof(drives));
	if (response == NULL)
	{
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	if (get_drives == NULL || get_type == NULL || get_space == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
		goto finish;
	}
	if (get_drives(sizeof(drives) / sizeof(drives[0]), drives) == 0)
	{
		result = micro_last_error();
		goto finish;
	}
	for (drive = drives; *drive != L'\0'; drive += micro_wide_length(drive) + 1)
	{
		Packet* group = mount_api->packet.create_group();
		char* name = micro_wide_to_utf8(mount_api, drive);
		ULARGE_INTEGER available;
		ULARGE_INTEGER total;
		ULARGE_INTEGER free_bytes;
		UINT type = get_type(drive);
		if (group == NULL || name == NULL)
		{
			mount_api->packet.destroy(group);
			micro_free(mount_api, name);
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		mount_api->packet.add_tlv_string(group, TLV_TYPE_MOUNT_NAME, name);
		mount_api->packet.add_tlv_uint(group, TLV_TYPE_MOUNT_TYPE, type);
		if (get_space(drive, &available, &total, &free_bytes))
		{
			mount_api->packet.add_tlv_qword(group, TLV_TYPE_MOUNT_SPACE_USER, available.QuadPart);
			mount_api->packet.add_tlv_qword(group, TLV_TYPE_MOUNT_SPACE_TOTAL, total.QuadPart);
			mount_api->packet.add_tlv_qword(group, TLV_TYPE_MOUNT_SPACE_FREE, free_bytes.QuadPart);
		}
		if (type == DRIVE_REMOTE && get_universal != NULL)
		{
			BYTE universal_buffer[1024];
			DWORD universal_size = sizeof(universal_buffer);
			if (get_universal(drive, UNIVERSAL_NAME_INFO_LEVEL, universal_buffer, &universal_size) == NO_ERROR)
			{
				char* unc = micro_wide_to_utf8(mount_api, ((MicroUniversalName*)universal_buffer)->name);
				if (unc != NULL)
				{
					mount_api->packet.add_tlv_string(group, TLV_TYPE_MOUNT_UNCPATH, unc);
					micro_free(mount_api, unc);
				}
			}
		}
		mount_api->packet.add_group(response, TLV_TYPE_MOUNT, group);
		micro_free(mount_api, name);
	}

finish:
	return mount_api->packet.transmit_response(result, remote, response);
}

static BOOL mount_show_inline(Remote* remote, Packet* packet, DWORD* result)
{
	*result = mount_show(remote, packet);
	return TRUE;
}

static Command mount_commands[] =
{
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_MOUNT_SHOW, mount_show_inline),
	COMMAND_TERMINATOR
};

static MicroExtension mount_extension =
{
	sizeof(MicroExtension), MICRO_EXTENSION_ABI_VERSION, "micro-stdapi-fs-mount", 1, mount_commands, MICRO_EXTENSION_FLAG_INLINE_HANDLERS
};

const MicroExtension* micro_init(MetApi* api, Remote* remote)
{
	(void)remote;
	if (api == NULL || api->packet.create_group == NULL || api->packet.create_response == NULL || api->packet.add_group == NULL || api->packet.add_tlv_string == NULL || api->packet.add_tlv_uint == NULL || api->packet.add_tlv_qword == NULL || api->packet.transmit_response == NULL || api->packet.destroy == NULL)
	{
		return NULL;
	}
	mount_api = api;
	return &mount_extension;
}

DWORD micro_deinit(Remote* remote)
{
	(void)remote;
	mount_api = NULL;
	return ERROR_SUCCESS;
}
