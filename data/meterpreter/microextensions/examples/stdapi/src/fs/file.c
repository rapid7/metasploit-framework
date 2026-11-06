#include "meterpreter_micro.h"
#include "micro_runtime.h"
#include "micro_stdapi.h"

typedef HANDLE (WINAPI* CreateFileWFunction)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI* ReadFileFunction)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI* WriteFileFunction)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI* CloseHandleFunction)(HANDLE);
typedef BOOL (WINAPI* SetFilePointerExFunction)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
typedef BOOL (WINAPI* GetFileSizeExFunction)(HANDLE, PLARGE_INTEGER);
typedef DWORD (WINAPI* ExpandEnvironmentStringsWFunction)(LPCWSTR, LPWSTR, DWORD);

typedef struct _FileContext
{
	HANDLE handle;
} FileContext;

static MetApi* file_api;

static wchar_t* file_path(const char* path)
{
	ExpandEnvironmentStringsWFunction expand;
	wchar_t* wide;
	wchar_t* expanded;
	DWORD required;

	wide = micro_utf8_to_wide(file_api, path);
	if (wide == NULL)
	{
		return NULL;
	}
	expand = (ExpandEnvironmentStringsWFunction)micro_resolve(file_api, "kernel32.dll", "ExpandEnvironmentStringsW");
	if (expand == NULL)
	{
		return wide;
	}
	required = expand(wide, NULL, 0);
	if (required == 0)
	{
		micro_free(file_api, wide);
		return NULL;
	}
	expanded = (wchar_t*)micro_alloc(file_api, (SIZE_T)required * sizeof(wchar_t));
	if (expanded == NULL || expand(wide, expanded, required) == 0)
	{
		micro_free(file_api, expanded);
		expanded = NULL;
	}
	micro_free(file_api, wide);
	return expanded;
}

static BOOL file_mode_has(const char* mode, char expected)
{
	while (mode != NULL && *mode != '\0')
	{
		if (*mode++ == expected)
		{
			return TRUE;
		}
	}
	return FALSE;
}

static DWORD file_channel_write(Channel* channel, Packet* packet, LPVOID context, LPVOID buffer, DWORD size, LPDWORD written)
{
	FileContext* file = (FileContext*)context;
	WriteFileFunction write_file = (WriteFileFunction)micro_resolve(file_api, "kernel32.dll", "WriteFile");
	DWORD count = 0;
	(void)channel;
	(void)packet;
	if (write_file == NULL)
	{
		return ERROR_PROC_NOT_FOUND;
	}
	if (size > 0 && !write_file(file->handle, buffer, size, &count, NULL))
	{
		return micro_last_error();
	}
	if (written != NULL)
	{
		*written = count;
	}
	return ERROR_SUCCESS;
}

static DWORD file_channel_close(Channel* channel, Packet* packet, LPVOID context)
{
	FileContext* file = (FileContext*)context;
	CloseHandleFunction close_handle = (CloseHandleFunction)micro_resolve(file_api, "kernel32.dll", "CloseHandle");
	DWORD result = ERROR_SUCCESS;
	(void)channel;
	(void)packet;
	if (close_handle == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
	}
	else if (!close_handle(file->handle))
	{
		result = micro_last_error();
	}
	micro_free(file_api, file);
	return result;
}

static DWORD file_channel_read(Channel* channel, Packet* packet, LPVOID context, LPVOID buffer, DWORD size, LPDWORD read)
{
	FileContext* file = (FileContext*)context;
	ReadFileFunction read_file = (ReadFileFunction)micro_resolve(file_api, "kernel32.dll", "ReadFile");
	DWORD count = 0;
	(void)channel;
	(void)packet;
	if (read_file == NULL)
	{
		return ERROR_PROC_NOT_FOUND;
	}
	if (size > 0 && !read_file(file->handle, buffer, size, &count, NULL))
	{
		return micro_last_error();
	}
	if (read != NULL)
	{
		*read = count;
	}
	return ERROR_SUCCESS;
}

static DWORD file_channel_eof(Channel* channel, Packet* packet, LPVOID context, LPBOOL is_eof)
{
	FileContext* file = (FileContext*)context;
	SetFilePointerExFunction set_pointer = (SetFilePointerExFunction)micro_resolve(file_api, "kernel32.dll", "SetFilePointerEx");
	GetFileSizeExFunction get_size = (GetFileSizeExFunction)micro_resolve(file_api, "kernel32.dll", "GetFileSizeEx");
	LARGE_INTEGER zero;
	LARGE_INTEGER position;
	LARGE_INTEGER size;
	(void)channel;
	(void)packet;
	zero.QuadPart = 0;
	if (set_pointer == NULL || get_size == NULL)
	{
		return ERROR_PROC_NOT_FOUND;
	}
	if (!set_pointer(file->handle, zero, &position, FILE_CURRENT) || !get_size(file->handle, &size))
	{
		return micro_last_error();
	}
	if (is_eof != NULL)
	{
		*is_eof = position.QuadPart >= size.QuadPart;
	}
	return ERROR_SUCCESS;
}

static DWORD file_channel_seek(Channel* channel, Packet* packet, LPVOID context, LONG offset, DWORD whence)
{
	FileContext* file = (FileContext*)context;
	SetFilePointerExFunction set_pointer = (SetFilePointerExFunction)micro_resolve(file_api, "kernel32.dll", "SetFilePointerEx");
	LARGE_INTEGER distance;
	(void)channel;
	(void)packet;
	distance.QuadPart = offset;
	if (set_pointer == NULL)
	{
		return ERROR_PROC_NOT_FOUND;
	}
	return set_pointer(file->handle, distance, NULL, whence) ? ERROR_SUCCESS : micro_last_error();
}

static DWORD file_channel_tell(Channel* channel, Packet* packet, LPVOID context, LPLONG offset)
{
	FileContext* file = (FileContext*)context;
	SetFilePointerExFunction set_pointer = (SetFilePointerExFunction)micro_resolve(file_api, "kernel32.dll", "SetFilePointerEx");
	LARGE_INTEGER zero;
	LARGE_INTEGER position;
	(void)channel;
	(void)packet;
	zero.QuadPart = 0;
	if (set_pointer == NULL)
	{
		return ERROR_PROC_NOT_FOUND;
	}
	if (!set_pointer(file->handle, zero, &position, FILE_CURRENT))
	{
		return micro_last_error();
	}
	if (position.QuadPart > LONG_MAX)
	{
		return ERROR_ARITHMETIC_OVERFLOW;
	}
	if (offset != NULL)
	{
		*offset = position.LowPart;
	}
	return ERROR_SUCCESS;
}

static DWORD file_channel_open(Remote* remote, Packet* packet, Channel** output)
{
	CreateFileWFunction create_file = (CreateFileWFunction)micro_resolve(file_api, "kernel32.dll", "CreateFileW");
	CloseHandleFunction close_handle = (CloseHandleFunction)micro_resolve(file_api, "kernel32.dll", "CloseHandle");
	SetFilePointerExFunction set_pointer = (SetFilePointerExFunction)micro_resolve(file_api, "kernel32.dll", "SetFilePointerEx");
	const char* path = file_api->packet.get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);
	const char* mode = file_api->packet.get_tlv_value_string(packet, TLV_TYPE_FILE_MODE);
	wchar_t* wide_path;
	FileContext* file;
	PoolChannelOps operations;
	LARGE_INTEGER zero;
	DWORD access;
	DWORD disposition;
	DWORD flags = file_api->packet.get_tlv_value_uint(packet, TLV_TYPE_FLAGS);
	BOOL update;
	(void)remote;
	if (output == NULL || path == NULL || create_file == NULL || close_handle == NULL)
	{
		return ERROR_INVALID_PARAMETER;
	}
	*output = NULL;
	mode = mode == NULL ? "rb" : mode;
	update = file_mode_has(mode, '+');
	if (*mode == 'r')
	{
		access = GENERIC_READ | (update ? GENERIC_WRITE : 0);
		disposition = OPEN_EXISTING;
	}
	else if (*mode == 'w')
	{
		access = GENERIC_WRITE | (update ? GENERIC_READ : 0);
		disposition = CREATE_ALWAYS;
	}
	else if (*mode == 'a')
	{
		access = GENERIC_WRITE | (update ? GENERIC_READ : 0);
		disposition = OPEN_ALWAYS;
	}
	else
	{
		return ERROR_INVALID_PARAMETER;
	}
	wide_path = file_path(path);
	file = (FileContext*)micro_alloc(file_api, sizeof(FileContext));
	if (wide_path == NULL || file == NULL)
	{
		micro_free(file_api, wide_path);
		micro_free(file_api, file);
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	file->handle = create_file(wide_path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, disposition, FILE_ATTRIBUTE_NORMAL, NULL);
	micro_free(file_api, wide_path);
	if (file->handle == INVALID_HANDLE_VALUE)
	{
		DWORD result = micro_last_error();
		micro_free(file_api, file);
		return result;
	}
	if (*mode == 'a')
	{
		zero.QuadPart = 0;
		if (set_pointer == NULL || !set_pointer(file->handle, zero, NULL, FILE_END))
		{
			DWORD result = set_pointer == NULL ? ERROR_PROC_NOT_FOUND : micro_last_error();
			close_handle(file->handle);
			micro_free(file_api, file);
			return result;
		}
	}
	micro_zero(&operations, sizeof(operations));
	operations.native.context = file;
	operations.native.write = file_channel_write;
	operations.native.close = file_channel_close;
	operations.read = file_channel_read;
	operations.eof = file_channel_eof;
	operations.seek = file_channel_seek;
	operations.tell = file_channel_tell;
	*output = file_api->channel.create_pool(0, flags, &operations);
	if (*output == NULL)
	{
		close_handle(file->handle);
		micro_free(file_api, file);
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	return ERROR_SUCCESS;
}

static MicroChannelProvider file_providers[] =
{
	{ "stdapi_fs_file", file_channel_open }
};

static MicroExtension file_extension =
{
	sizeof(MicroExtension),
	MICRO_EXTENSION_ABI_VERSION,
	"micro-stdapi-file-channel",
	0,
	NULL,
	MICRO_EXTENSION_FLAG_INLINE_HANDLERS,
	1,
	file_providers
};

const MicroExtension* micro_init(MetApi* api, Remote* remote)
{
	(void)remote;
	if (api == NULL || api->packet.get_tlv_value_string == NULL || api->packet.get_tlv_value_uint == NULL || api->channel.create_pool == NULL)
	{
		return NULL;
	}
	file_api = api;
	return &file_extension;
}

DWORD micro_deinit(Remote* remote)
{
	(void)remote;
	file_api = NULL;
	return ERROR_SUCCESS;
}
