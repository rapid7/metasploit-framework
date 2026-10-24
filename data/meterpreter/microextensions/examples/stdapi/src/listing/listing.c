#include "meterpreter_micro.h"
#include "micro_runtime.h"
#include "micro_stdapi.h"

#define MICRO_IFDIR 0x4000
#define MICRO_IFREG 0x8000

typedef DWORD(WINAPI* ExpandEnvironmentStringsWFunction)(LPCWSTR source, LPWSTR destination, DWORD size);
typedef DWORD(WINAPI* GetCurrentDirectoryWFunction)(DWORD size, LPWSTR buffer);
typedef HANDLE(WINAPI* FindFirstFileWFunction)(LPCWSTR path, LPWIN32_FIND_DATAW data);
typedef BOOL(WINAPI* FindNextFileWFunction)(HANDLE handle, LPWIN32_FIND_DATAW data);
typedef BOOL(WINAPI* FindCloseFunction)(HANDLE handle);
typedef BOOL(WINAPI* GetFileAttributesExWFunction)(LPCWSTR path, GET_FILEEX_INFO_LEVELS level, LPVOID data);
typedef BOOLEAN(NTAPI* RtlTimeToSecondsSince1970Function)(PLARGE_INTEGER time, PULONG seconds);

static MetApi* listing_api;

static wchar_t* listing_duplicate(const wchar_t* value, SIZE_T extra_characters)
{
	SIZE_T length = micro_wide_length(value);
	wchar_t* copy = (wchar_t*)micro_alloc(listing_api, (length + extra_characters + 1) * sizeof(wchar_t));
	if (copy != NULL)
	{
		micro_copy(copy, value, (length + 1) * sizeof(wchar_t));
	}
	return copy;
}

static wchar_t* listing_expand_path(const char* path)
{
	ExpandEnvironmentStringsWFunction expand_environment;
	wchar_t* wide_path;
	wchar_t* expanded;
	DWORD required;

	wide_path = micro_utf8_to_wide(listing_api, path);
	if (wide_path == NULL)
	{
		return NULL;
	}

	expand_environment = (ExpandEnvironmentStringsWFunction)micro_resolve(listing_api, "kernel32.dll", "ExpandEnvironmentStringsW");
	if (expand_environment == NULL)
	{
		return wide_path;
	}

	required = expand_environment(wide_path, NULL, 0);
	if (required == 0)
	{
		micro_free(listing_api, wide_path);
		return NULL;
	}

	expanded = (wchar_t*)micro_alloc(listing_api, (SIZE_T)required * sizeof(wchar_t));
	if (expanded == NULL || expand_environment(wide_path, expanded, required) == 0)
	{
		micro_free(listing_api, expanded);
		expanded = NULL;
	}

	micro_free(listing_api, wide_path);
	return expanded;
}

static BOOL listing_extension_equal(const wchar_t* extension, const wchar_t* expected)
{
	while (*extension != L'\0' && *expected != L'\0')
	{
		wchar_t left = *extension >= L'A' && *extension <= L'Z' ? *extension + (L'a' - L'A') : *extension;
		wchar_t right = *expected >= L'A' && *expected <= L'Z' ? *expected + (L'a' - L'A') : *expected;
		if (left != right)
		{
			return FALSE;
		}
		extension++;
		expected++;
	}
	return *extension == *expected;
}

static void listing_filetime(const FILETIME* filetime, uint64_t* output)
{
	RtlTimeToSecondsSince1970Function time_to_seconds = (RtlTimeToSecondsSince1970Function)micro_resolve(listing_api, "ntdll.dll", "RtlTimeToSecondsSince1970");
	LARGE_INTEGER ticks;
	ULONG seconds = 0;

	ticks.HighPart = (LONG)filetime->dwHighDateTime;
	ticks.LowPart = filetime->dwLowDateTime;
	if (time_to_seconds != NULL)
	{
		time_to_seconds(&ticks, &seconds);
	}
	*output = seconds;
}

static void listing_stat_from_data(const WIN32_FILE_ATTRIBUTE_DATA* data, const wchar_t* path, MicroMeterpStat* result)
{
	const wchar_t* extension = NULL;
	const wchar_t* current = path;
	micro_zero(result, sizeof(*result));
	result->st_mode = (data->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? MICRO_IFDIR | 0111 : MICRO_IFREG;
	result->st_mode |= (data->dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? 0444 : 0666;
	result->st_size = ((uint64_t)data->nFileSizeHigh << 32) | data->nFileSizeLow;
	listing_filetime(&data->ftCreationTime, &result->st_ctime);
	listing_filetime(&data->ftLastWriteTime, &result->st_mtime);
	listing_filetime(&data->ftLastAccessTime, &result->st_atime);

	while (*current != L'\0')
	{
		if (*current == L'.')
		{
			extension = current;
		}
		current++;
	}
	if (extension != NULL && (listing_extension_equal(extension, L".bat") || listing_extension_equal(extension, L".cmd") || listing_extension_equal(extension, L".com") || listing_extension_equal(extension, L".exe")))
	{
		result->st_mode |= 0111;
	}
}

static DWORD listing_stat_wide(const wchar_t* path, MicroMeterpStat* result)
{
	GetFileAttributesExWFunction get_attributes;
	WIN32_FILE_ATTRIBUTE_DATA data;
	get_attributes = (GetFileAttributesExWFunction)micro_resolve(listing_api, "kernel32.dll", "GetFileAttributesExW");
	if (get_attributes == NULL)
	{
		return ERROR_PROC_NOT_FOUND;
	}
	if (!get_attributes(path, GetFileExInfoStandard, &data))
	{
		return micro_last_error();
	}
	listing_stat_from_data(&data, path, result);
	return ERROR_SUCCESS;
}

static DWORD listing_getwd(Remote* remote, Packet* packet)
{
	GetCurrentDirectoryWFunction get_current_directory;
	Packet* response = listing_api->packet.create_response(packet);
	wchar_t* wide_path = NULL;
	char* path = NULL;
	DWORD required;
	DWORD result = ERROR_SUCCESS;

	get_current_directory = (GetCurrentDirectoryWFunction)micro_resolve(listing_api, "kernel32.dll", "GetCurrentDirectoryW");
	if (response == NULL || get_current_directory == NULL)
	{
		return response == NULL ? ERROR_INVALID_HANDLE : ERROR_PROC_NOT_FOUND;
	}

	required = get_current_directory(0, NULL);
	wide_path = (wchar_t*)micro_alloc(listing_api, (SIZE_T)required * sizeof(wchar_t));
	if (required == 0 || wide_path == NULL)
	{
		result = required == 0 ? micro_last_error() : ERROR_NOT_ENOUGH_MEMORY;
	}
	else if (get_current_directory(required, wide_path) == 0)
	{
		result = micro_last_error();
	}
	else
	{
		path = micro_wide_to_utf8(listing_api, wide_path);
		if (path == NULL)
		{
			result = ERROR_NO_UNICODE_TRANSLATION;
		}
		else
		{
			listing_api->packet.add_tlv_string(response, TLV_TYPE_DIRECTORY_PATH, path);
		}
	}

	result = listing_api->packet.transmit_response(result, remote, response);
	micro_free(listing_api, path);
	micro_free(listing_api, wide_path);
	return result;
}

static wchar_t* listing_pattern(wchar_t* directory, wchar_t** base_directory)
{
	SIZE_T length = micro_wide_length(directory);
	SIZE_T last_separator = (SIZE_T)-1;
	SIZE_T index;
	BOOL wildcard = FALSE;
	wchar_t* pattern;

	for (index = 0; index < length; index++)
	{
		if (directory[index] == L'\\' || directory[index] == L'/')
		{
			last_separator = index;
		}
		if (directory[index] == L'*' || directory[index] == L'?')
		{
			wildcard = TRUE;
		}
	}

	pattern = listing_duplicate(directory, wildcard ? 0 : 2);
	if (pattern == NULL)
	{
		return NULL;
	}

	if (wildcard)
	{
		SIZE_T base_length = last_separator == (SIZE_T)-1 ? 0 : last_separator;
		if (base_length == 2 && directory[1] == L':')
		{
			base_length++;
		}
		*base_directory = (wchar_t*)micro_alloc(listing_api, (base_length + 1) * sizeof(wchar_t));
		if (*base_directory != NULL && base_length > 0)
		{
			micro_copy(*base_directory, directory, base_length * sizeof(wchar_t));
		}
	}
	else
	{
		*base_directory = listing_duplicate(directory, 0);
		if (length > 0 && pattern[length - 1] != L'\\' && pattern[length - 1] != L'/')
		{
			pattern[length++] = L'\\';
		}
		pattern[length++] = L'*';
		pattern[length] = L'\0';
	}

	if (*base_directory == NULL)
	{
		micro_free(listing_api, pattern);
		pattern = NULL;
	}
	return pattern;
}

static wchar_t* listing_join(const wchar_t* base_directory, const wchar_t* name)
{
	SIZE_T base_length = micro_wide_length(base_directory);
	SIZE_T name_length = micro_wide_length(name);
	BOOL separator = base_length > 0 && base_directory[base_length - 1] != L'\\' && base_directory[base_length - 1] != L'/';
	wchar_t* path = (wchar_t*)micro_alloc(listing_api, (base_length + name_length + (separator ? 2 : 1)) * sizeof(wchar_t));
	if (path != NULL)
	{
		micro_copy(path, base_directory, base_length * sizeof(wchar_t));
		if (separator)
		{
			path[base_length++] = L'\\';
		}
		micro_copy(path + base_length, name, (name_length + 1) * sizeof(wchar_t));
	}
	return path;
}

static DWORD listing_ls(Remote* remote, Packet* packet)
{
	FindFirstFileWFunction find_first;
	FindNextFileWFunction find_next;
	FindCloseFunction find_close;
	Packet* response = listing_api->packet.create_response(packet);
	const char* requested = listing_api->packet.get_tlv_value_string(packet, TLV_TYPE_DIRECTORY_PATH);
	wchar_t* directory = NULL;
	wchar_t* base_directory = NULL;
	wchar_t* pattern = NULL;
	HANDLE find_handle = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW data;
	DWORD result = ERROR_SUCCESS;

	find_first = (FindFirstFileWFunction)micro_resolve(listing_api, "kernel32.dll", "FindFirstFileW");
	find_next = (FindNextFileWFunction)micro_resolve(listing_api, "kernel32.dll", "FindNextFileW");
	find_close = (FindCloseFunction)micro_resolve(listing_api, "kernel32.dll", "FindClose");
	if (response == NULL || requested == NULL)
	{
		result = ERROR_INVALID_PARAMETER;
		goto finish;
	}
	if (find_first == NULL || find_next == NULL || find_close == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
		goto finish;
	}

	directory = listing_expand_path(requested);
	pattern = directory == NULL ? NULL : listing_pattern(directory, &base_directory);
	if (pattern == NULL)
	{
		result = ERROR_NOT_ENOUGH_MEMORY;
		goto finish;
	}

	find_handle = find_first(pattern, &data);
	if (find_handle == INVALID_HANDLE_VALUE)
	{
		result = micro_last_error();
		goto finish;
	}

	do
	{
		wchar_t* wide_path = listing_join(base_directory, data.cFileName);
		char* name = micro_wide_to_utf8(listing_api, data.cFileName);
		char* short_name = micro_wide_to_utf8(listing_api, data.cAlternateFileName);
		char* path = micro_wide_to_utf8(listing_api, wide_path);
		MicroMeterpStat stat_buffer;

		if (wide_path == NULL || name == NULL || path == NULL)
		{
			micro_free(listing_api, path);
			micro_free(listing_api, short_name);
			micro_free(listing_api, name);
			micro_free(listing_api, wide_path);
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		WIN32_FILE_ATTRIBUTE_DATA attributes;
		attributes.dwFileAttributes = data.dwFileAttributes;
		attributes.ftCreationTime = data.ftCreationTime;
		attributes.ftLastAccessTime = data.ftLastAccessTime;
		attributes.ftLastWriteTime = data.ftLastWriteTime;
		attributes.nFileSizeHigh = data.nFileSizeHigh;
		attributes.nFileSizeLow = data.nFileSizeLow;
		listing_stat_from_data(&attributes, wide_path, &stat_buffer);
		listing_api->packet.add_tlv_string(response, TLV_TYPE_FILE_NAME, name);
		listing_api->packet.add_tlv_string(response, TLV_TYPE_FILE_PATH, path);
		listing_api->packet.add_tlv_string(response, TLV_TYPE_FILE_SHORT_NAME, short_name);
		listing_api->packet.add_tlv_raw(response, TLV_TYPE_STAT_BUF, &stat_buffer, sizeof(stat_buffer));

		micro_free(listing_api, path);
		micro_free(listing_api, short_name);
		micro_free(listing_api, name);
		micro_free(listing_api, wide_path);
	} while (find_next(find_handle, &data));

	if (result == ERROR_SUCCESS && micro_last_error() != ERROR_NO_MORE_FILES)
	{
		result = micro_last_error();
	}

finish:
	if (find_handle != INVALID_HANDLE_VALUE && find_close != NULL)
	{
		find_close(find_handle);
	}
	result = response == NULL ? result : listing_api->packet.transmit_response(result, remote, response);
	micro_free(listing_api, pattern);
	micro_free(listing_api, base_directory);
	micro_free(listing_api, directory);
	return result;
}

static DWORD listing_stat(Remote* remote, Packet* packet)
{
	Packet* response = listing_api->packet.create_response(packet);
	const char* requested = listing_api->packet.get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);
	wchar_t* path = NULL;
	MicroMeterpStat stat_buffer;
	DWORD result;

	if (response == NULL || requested == NULL)
	{
		result = ERROR_INVALID_PARAMETER;
	}
	else
	{
		path = listing_expand_path(requested);
		result = path == NULL ? ERROR_NOT_ENOUGH_MEMORY : listing_stat_wide(path, &stat_buffer);
		if (result == ERROR_SUCCESS)
		{
			listing_api->packet.add_tlv_raw(response, TLV_TYPE_STAT_BUF, &stat_buffer, sizeof(stat_buffer));
		}
	}

	result = response == NULL ? result : listing_api->packet.transmit_response(result, remote, response);
	micro_free(listing_api, path);
	return result;
}

static BOOL listing_getwd_inline(Remote* remote, Packet* packet, DWORD* result)
{
	*result = listing_getwd(remote, packet);
	return TRUE;
}

static BOOL listing_ls_inline(Remote* remote, Packet* packet, DWORD* result)
{
	*result = listing_ls(remote, packet);
	return TRUE;
}

static BOOL listing_stat_inline(Remote* remote, Packet* packet, DWORD* result)
{
	*result = listing_stat(remote, packet);
	return TRUE;
}

static Command listing_commands[] =
{
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_GETWD, listing_getwd_inline),
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_LS, listing_ls_inline),
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_STAT, listing_stat_inline),
	COMMAND_TERMINATOR
};

static MicroExtension listing_extension =
{
	sizeof(MicroExtension),
	MICRO_EXTENSION_ABI_VERSION,
	"micro-stdapi-listing",
	3,
	listing_commands,
	MICRO_EXTENSION_FLAG_INLINE_HANDLERS
};

const MicroExtension* micro_init(MetApi* api, Remote* remote)
{
	(void)remote;
	if (api == NULL || api->packet.create_response == NULL || api->packet.get_tlv_value_string == NULL || api->packet.add_tlv_string == NULL || api->packet.add_tlv_raw == NULL || api->packet.transmit_response == NULL)
	{
		return NULL;
	}

	listing_api = api;
	return &listing_extension;
}

DWORD micro_deinit(Remote* remote)
{
	(void)remote;
	listing_api = NULL;
	return ERROR_SUCCESS;
}
