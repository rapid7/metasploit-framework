#ifndef MICRO_RUNTIME_H
#define MICRO_RUNTIME_H

#include "meterpreter_micro.h"

static void micro_zero(void* buffer, SIZE_T length)
{
	BYTE* current = (BYTE*)buffer;
	while (length-- > 0)
	{
		*current++ = 0;
	}
}

static SIZE_T micro_string_length(const char* value)
{
	SIZE_T length = 0;
	if (value != NULL)
	{
		while (value[length] != '\0')
		{
			length++;
		}
	}
	return length;
}

static BOOL micro_string_equal(const char* left, const char* right)
{
	if (left == NULL || right == NULL)
	{
		return FALSE;
	}

	while (*left != '\0' && *right != '\0' && *left == *right)
	{
		left++;
		right++;
	}

	return *left == *right;
}

static SIZE_T micro_wide_length(const wchar_t* value)
{
	SIZE_T length = 0;
	if (value != NULL)
	{
		while (value[length] != L'\0')
		{
			length++;
		}
	}
	return length;
}

static void micro_copy(void* destination, const void* source, SIZE_T length)
{
	BYTE* output = (BYTE*)destination;
	const BYTE* input = (const BYTE*)source;
	while (length-- > 0)
	{
		*output++ = *input++;
	}
}

static void* micro_alloc(MetApi* api, SIZE_T size)
{
	HANDLE heap;
	if (api == NULL || size == 0 || api->win_api.kernel32.GetProcessHeap == NULL || api->win_api.kernel32.HeapAlloc == NULL)
	{
		return NULL;
	}

	heap = api->win_api.kernel32.GetProcessHeap();
	return heap == NULL ? NULL : api->win_api.kernel32.HeapAlloc(heap, HEAP_ZERO_MEMORY, size);
}

static void micro_free(MetApi* api, void* buffer)
{
	HANDLE heap;
	if (api == NULL || buffer == NULL || api->win_api.kernel32.GetProcessHeap == NULL || api->win_api.kernel32.HeapFree == NULL)
	{
		return;
	}

	heap = api->win_api.kernel32.GetProcessHeap();
	if (heap != NULL)
	{
		api->win_api.kernel32.HeapFree(heap, 0, buffer);
	}
}

static DWORD micro_last_error(void)
{
	DWORD value = ERROR_SUCCESS;
#ifdef _WIN64
	__asm__ volatile("movl %%gs:0x68, %0" : "=r"(value));
#else
	__asm__ volatile("movl %%fs:0x34, %0" : "=r"(value));
#endif
	return value;
}

static void micro_set_last_error(DWORD value)
{
#ifdef _WIN64
	__asm__ volatile("movl %0, %%gs:0x68" : : "r"(value) : "memory");
#else
	__asm__ volatile("movl %0, %%fs:0x34" : : "r"(value) : "memory");
#endif
}

static FARPROC micro_resolve_internal(MetApi* api, const char* module_name, const char* symbol_name, WORD ordinal, BOOL by_ordinal, DWORD depth)
{
	BYTE* image;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_headers;
	PIMAGE_EXPORT_DIRECTORY export_directory;
	DWORD export_rva;
	DWORD export_size;
	DWORD function_index = 0;
	DWORD* functions;
	DWORD function_rva;

	if (api == NULL || module_name == NULL || depth > 4 || api->win_api.kernel32.GetModuleHandleA == NULL || api->win_api.kernel32.LoadLibraryA == NULL)
	{
		return NULL;
	}

	image = (BYTE*)api->win_api.kernel32.GetModuleHandleA(module_name);
	if (image == NULL)
	{
		image = (BYTE*)api->win_api.kernel32.LoadLibraryA(module_name);
	}
	if (image == NULL)
	{
		return NULL;
	}

	dos_header = (PIMAGE_DOS_HEADER)image;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	nt_headers = (PIMAGE_NT_HEADERS)(image + dos_header->e_lfanew);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	export_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	export_size = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (export_rva == 0 || export_size == 0)
	{
		return NULL;
	}

	export_directory = (PIMAGE_EXPORT_DIRECTORY)(image + export_rva);
	functions = (DWORD*)(image + export_directory->AddressOfFunctions);
	if (by_ordinal)
	{
		if (ordinal < export_directory->Base || ordinal - export_directory->Base >= export_directory->NumberOfFunctions)
		{
			return NULL;
		}
		function_index = ordinal - export_directory->Base;
	}
	else
	{
		DWORD name_index;
		DWORD* names = (DWORD*)(image + export_directory->AddressOfNames);
		WORD* ordinals = (WORD*)(image + export_directory->AddressOfNameOrdinals);
		BOOL found = FALSE;

		for (name_index = 0; name_index < export_directory->NumberOfNames; name_index++)
		{
			if (micro_string_equal((const char*)(image + names[name_index]), symbol_name))
			{
				function_index = ordinals[name_index];
				found = TRUE;
				break;
			}
		}
		if (!found || function_index >= export_directory->NumberOfFunctions)
		{
			return NULL;
		}
	}

	function_rva = functions[function_index];
	if (function_rva >= export_rva && function_rva < export_rva + export_size)
	{
		const char* forwarder = (const char*)(image + function_rva);
		char forward_module[64];
		char forward_symbol[128];
		SIZE_T split = 0;
		SIZE_T index;

		while (forwarder[split] != '\0' && forwarder[split] != '.')
		{
			split++;
		}
		if (split == 0 || split >= sizeof(forward_module) - 5 || forwarder[split] == '\0')
		{
			return NULL;
		}

		for (index = 0; index < split; index++)
		{
			forward_module[index] = forwarder[index];
		}
		forward_module[split] = '.';
		forward_module[split + 1] = 'd';
		forward_module[split + 2] = 'l';
		forward_module[split + 3] = 'l';
		forward_module[split + 4] = '\0';

		index = 0;
		while (forwarder[split + 1 + index] != '\0' && index < sizeof(forward_symbol) - 1)
		{
			forward_symbol[index] = forwarder[split + 1 + index];
			index++;
		}
		forward_symbol[index] = '\0';

		if (forward_symbol[0] == '#')
		{
			WORD forward_ordinal = 0;
			index = 1;
			while (forward_symbol[index] >= '0' && forward_symbol[index] <= '9')
			{
				forward_ordinal = (WORD)(forward_ordinal * 10 + forward_symbol[index] - '0');
				index++;
			}
			return micro_resolve_internal(api, forward_module, NULL, forward_ordinal, TRUE, depth + 1);
		}

		return micro_resolve_internal(api, forward_module, forward_symbol, 0, FALSE, depth + 1);
	}

	return (FARPROC)(image + function_rva);
}

static FARPROC micro_resolve(MetApi* api, const char* module_name, const char* symbol_name)
{
	return micro_resolve_internal(api, module_name, symbol_name, 0, FALSE, 0);
}

static wchar_t* micro_utf8_to_wide(MetApi* api, const char* value)
{
	int required;
	wchar_t* converted;
	if (api == NULL || value == NULL || api->win_api.kernel32.MultiByteToWideChar == NULL)
	{
		return NULL;
	}

	required = api->win_api.kernel32.MultiByteToWideChar(CP_UTF8, 0, value, -1, NULL, 0);
	if (required <= 0)
	{
		return NULL;
	}

	converted = (wchar_t*)micro_alloc(api, (SIZE_T)required * sizeof(wchar_t));
	if (converted == NULL || api->win_api.kernel32.MultiByteToWideChar(CP_UTF8, 0, value, -1, converted, required) == 0)
	{
		micro_free(api, converted);
		return NULL;
	}
	return converted;
}

static char* micro_wide_to_utf8(MetApi* api, const wchar_t* value)
{
	int required;
	char* converted;
	if (api == NULL || value == NULL || api->win_api.kernel32.WideCharToMultiByte == NULL)
	{
		return NULL;
	}

	required = api->win_api.kernel32.WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
	if (required <= 0)
	{
		return NULL;
	}

	converted = (char*)micro_alloc(api, (SIZE_T)required);
	if (converted == NULL || api->win_api.kernel32.WideCharToMultiByte(CP_UTF8, 0, value, -1, converted, required, NULL, NULL) == 0)
	{
		micro_free(api, converted);
		return NULL;
	}
	return converted;
}

#endif
