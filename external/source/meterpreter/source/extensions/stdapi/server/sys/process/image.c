#include "precomp.h"

DWORD remote_load_library(HANDLE process, LPCSTR image,
		HMODULE *base);
DWORD remote_get_proc_address(HANDLE process, HMODULE module,
		LPCSTR symbol, LPVOID *address);
DWORD remote_unload_library(HANDLE process, HMODULE base);

/*
 * Loads an image file into the context of the supplied process.
 *
 * req: TLV_TYPE_HANDLE          - The process handle to load the image into.
 * req: TLV_TYPE_IMAGE_FILE_PATH - The path to the image file that is to be
 *                                 loaded.
 */
DWORD request_sys_process_image_load(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	HANDLE handle;
	LPCSTR image;
	HMODULE base;

	handle = (HANDLE)packet_get_tlv_value_uint(packet, TLV_TYPE_HANDLE);
	image  = packet_get_tlv_value_string(packet, TLV_TYPE_IMAGE_FILE_PATH);

	do
	{
		// Validate parameters
		if ((!handle) ||
		    (!image))
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// If the handle is not the current process, load the library
		// into the context of the remote process
		if (handle != GetCurrentProcess())
			result = remote_load_library(handle, image, &base);
		else
		{
			// Load the image file
			if (!(base = LoadLibrary(image)))
			{
				result = GetLastError();
				break;
			}
		}

		// Add the base address to the result
		packet_add_tlv_uint(response, TLV_TYPE_IMAGE_BASE, (DWORD)base);

	} while (0);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Returns the address of a procedure that is associated with the supplied
 * module to the requestor.
 *
 * req: TLV_TYPE_IMAGE_NAME     - The name of the image to query.
 * req: TLV_TYPE_PROCEDURE_NAME - The name of the procedure to query.
 */
DWORD request_sys_process_image_get_proc_address(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	HMODULE mod = NULL;
	BOOLEAN unload = FALSE;
	HANDLE process;
	LPCSTR image;
	LPCSTR procedure;
	LPVOID address = NULL;

	process   = (HANDLE)packet_get_tlv_value_uint(packet, TLV_TYPE_HANDLE);
	image     = packet_get_tlv_value_string(packet, TLV_TYPE_IMAGE_FILE);
	procedure = packet_get_tlv_value_string(packet, TLV_TYPE_PROCEDURE_NAME);

	do
	{
		// Validate parameters
		if ((!image) ||
		    (!procedure))
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// If the process handle is not this process...
		if (process != GetCurrentProcess())
		{
			if ((result = remote_load_library(process, image, 
					&mod)) != ERROR_SUCCESS)
				break;
			
			if ((result = remote_get_proc_address(process, mod, procedure,
					&address)) != ERROR_SUCCESS)
				break;
		}
		// Otherwise, load the library locally
		else
		{
			unload = TRUE;

			if (!(mod = LoadLibrary(image)))
			{
				result = GetLastError();
				break;
			}

			// Try to resolve the procedure name
			if (!(address = (LPVOID)GetProcAddress(mod, procedure)))
			{
				result = GetLastError();
				break;
			}
		}

		// Set the procedure address on the response
		packet_add_tlv_uint(response, TLV_TYPE_PROCEDURE_ADDRESS, 
				(DWORD)address);

	} while (0);

	// Lose the reference to the module
	if ((mod) &&
	    (unload))
		FreeLibrary(mod);
	else if (mod)
		remote_unload_library(process, mod);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Unloads an image file using the base address supplied by the requestor
 *
 * req: TLV_TYPE_HANDLE     - The process to unload the image in
 * req: TLV_TYPE_IMAGE_BASE - The base address of the image to unload
 */
DWORD request_sys_process_image_unload(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	HANDLE handle;
	LPVOID base;
	DWORD result = ERROR_SUCCESS;

	handle = (HANDLE)packet_get_tlv_value_uint(packet, TLV_TYPE_HANDLE);
	base   = (LPVOID)packet_get_tlv_value_uint(packet, TLV_TYPE_IMAGE_BASE);

	do
	{
		// Validate parameters
		if ((!handle) ||
		    (!base))
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		if (handle != GetCurrentProcess())
			result = remote_unload_library(handle, base);
		else
		{
			// Unload the library
			if (!FreeLibrary(base))
				result = GetLastError();
		}

	} while (0);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Returns a list of all of the loaded image files and their base addresses to
 * the requestor.
 *
 * req: TLV_TYPE_HANDLE - The process handle to enumerate the images of
 */
DWORD request_sys_process_image_get_images(Remote *remote, Packet *packet)
{
	BOOL (WINAPI *enumProcessModules)(HANDLE p, HMODULE *mod, DWORD cb, LPDWORD needed);
	DWORD (WINAPI *getModuleBaseName)(HANDLE p, HMODULE mod, LPTSTR base, 
			DWORD baseSize);
	DWORD (WINAPI *getModuleFileNameEx)(HANDLE p, HMODULE mod, LPTSTR path,
			DWORD pathSize);
	Packet *response = packet_create_response(packet);
	HMODULE *modules = NULL;
	BOOLEAN valid = FALSE;
	HANDLE psapi = NULL;
	HANDLE handle;
	DWORD result = ERROR_SUCCESS;
	DWORD needed = 0, actual, tries = 0;
	DWORD index;

	handle = (HANDLE)packet_get_tlv_value_uint(packet, TLV_TYPE_HANDLE);

	do
	{
		// No response?  No sense.
		if (!response)
			break;
		
		// Open the process API
		if (!(psapi = LoadLibrary("psapi")))
			break;

		// Try to resolve the address of EnumProcessModules
		if (!((LPVOID)enumProcessModules = 
				(LPVOID)GetProcAddress(psapi, "EnumProcessModules")))
			break;

		// Try to resolve the address of GetModuleBaseNameA
		if (!((LPVOID)getModuleBaseName = 
				(LPVOID)GetProcAddress(psapi, "GetModuleBaseNameA")))
			break;

		// Try to resolve the address of GetModuleFileNameExA
		if (!((LPVOID)getModuleFileNameEx = 
				(LPVOID)GetProcAddress(psapi, "GetModuleFileNameExA")))
			break;

		// Validate parameters
		if (!handle)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// The current actual size of the array in bytes
		actual = sizeof(HMODULE) * 512;

		do
		{
			// Free previous storage
			if (modules)
				free(modules);

			// Allocate storage for the array
			modules = (HMODULE *)malloc(actual);

			// Try to enumerate the image's modules
			if (enumProcessModules(handle, modules, actual, &needed))
			{
				valid = TRUE;
				break;
			}

		} while ((actual < needed) &&
		         (tries++ < 3));

		// If we failed to succeed...
		if (!valid)
		{
			result = GetLastError();
			break;
		}

		// Enumerate through all of the modules...
		for (index = 0;
		     index < needed / sizeof(HMODULE);
		     index++)
		{
			char  path[1024], name[512];
			DWORD base = 0;
			Tlv   tlvs[3];

			memset(name, 0, sizeof(name));
			memset(path, 0, sizeof(path));

			// Query for base name and file name
			if ((!getModuleBaseName(handle, modules[index], name,
					sizeof(name) - 1)) ||
			    (!getModuleFileNameEx(handle, modules[index], path,
					sizeof(path) - 1)))
			{
				result = GetLastError();
				break;
			}

			base = htonl((DWORD)modules[index]);

			tlvs[0].header.length = sizeof(HMODULE);
			tlvs[0].header.type   = TLV_TYPE_IMAGE_BASE;
			tlvs[0].buffer        = (PUCHAR)&base;
			tlvs[1].header.length = strlen(path) + 1;
			tlvs[1].header.type   = TLV_TYPE_IMAGE_FILE_PATH;
			tlvs[1].buffer        = (PUCHAR)path;
			tlvs[2].header.length = strlen(name) + 1;
			tlvs[2].header.type   = TLV_TYPE_IMAGE_NAME;
			tlvs[2].buffer        = (PUCHAR)name;

			packet_add_tlv_group(response, TLV_TYPE_IMAGE_GROUP, tlvs, 3);
		}

	} while (0);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	// Cleanup
	if (modules)
		free(modules);
	// Close the psapi library and clean up
	if (psapi)
		FreeLibrary(psapi);

	return ERROR_SUCCESS;
}

/*******************
 * Helper routines *
 *******************/

typedef struct _LoadLibraryContext
{
	LPVOID loadLibraryAddress;
	CHAR   imagePath[1];
} LoadLibraryContext;

typedef struct _GetProcAddressContext
{
	LPVOID  getProcAddress;
	HMODULE module;
	CHAR    symbol[1];
} GetProcAddressContext;

typedef struct _UnloadLibraryContext
{
	LPVOID  freeLibraryAddress;
	HMODULE module;
} UnloadLibraryContext;

/*
 * Loads a library into the context of a remote process
 */
DWORD remote_load_library(HANDLE process, LPCSTR image, HMODULE *base)
{
	LoadLibraryContext *context = NULL;
	DWORD result = ERROR_SUCCESS;
	DWORD contextSize = 0;
	BYTE loadLibraryStub[] =
		"\x8b\x54\x24\x04"  // see load_library_stub
		"\x8d\x5a\x04"
		"\x53"
		"\xff\x12"
		"\xc2\x04\x00";

	do
	{
		// Calculate the size of the context we'll be passing
		contextSize = strlen(image) + 1 + sizeof(LoadLibraryContext);

		if (!(context = (LoadLibraryContext *)malloc(contextSize)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Initialize the context
		context->loadLibraryAddress = (PVOID)GetProcAddress(
				GetModuleHandle("kernel32"), "LoadLibraryA");

		strcpy(context->imagePath, image);

		// Execute the LoadLibraryA stub
		result = execute_code_stub_in_process(process, (PVOID)loadLibraryStub, 
				sizeof(loadLibraryStub) - 1, context, contextSize, 
				(LPDWORD)base);	

	} while (0);

	if (context)
		free(context);

	return result;
}

/*
 * Gets the address of a procedure that exists in a remote
 * process
 */
DWORD remote_get_proc_address(HANDLE process, HMODULE module,
		LPCSTR symbol, LPVOID *address)
{
	GetProcAddressContext *context = NULL;
	DWORD result = ERROR_SUCCESS;
	DWORD contextSize = 0;
	BYTE getProcAddressStub[] =
		"\x8b\x54\x24\x04"  // see unload_library_stub
		"\x8b\x5a\x04"
		"\x8d\x4a\x08"
		"\x51"
		"\x53"
		"\xff\x12"
		"\xc2\x04\x00";

	do
	{
		// Calculate the size of the context we'll be passing
		contextSize = strlen(symbol) + 1 + sizeof(GetProcAddressContext);

		if (!(context = (GetProcAddressContext *)malloc(contextSize)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Initialize the context
		context->getProcAddress = (PVOID)GetProcAddress(
				GetModuleHandle("kernel32"), "GetProcAddress");
		context->module = module;

		strcpy(context->symbol, symbol);

		// Execute the LoadLibraryA stub
		result = execute_code_stub_in_process(process, (PVOID)getProcAddressStub,
				sizeof(getProcAddressStub) - 1, context, contextSize, 
				(LPDWORD)address);

	} while (0);

	if (context)
		free(context);

	return result;
}

/*
 * Unloads a library in the context of a remote process
 */
DWORD remote_unload_library(HANDLE process, HMODULE base)
{
	UnloadLibraryContext context;
	DWORD result = ERROR_SUCCESS;
	BYTE unloadLibraryStub[] =
		"\x8b\x54\x24\x04"  // see unload_library_stub
		"\xff\x72\x04"
		"\xff\x12"
		"\xc2\x04\x00";

	do
	{
		// Initialize the context
		context.freeLibraryAddress = (PVOID)GetProcAddress(
				GetModuleHandle("kernel32"), "FreeLibrary");

		context.module = base;

		// Execute the FreeLibrary stub
		result = execute_code_stub_in_process(process, (PVOID)unloadLibraryStub, 
				sizeof(unloadLibraryStub) - 1, &context, sizeof(context),
				NULL);

	} while (0);

	return result;
}

/***********************
 * Internal code stubs *
 ***********************/

#if 0
VOID __declspec(naked) load_library_stub()
{
	__asm
	{
		mov  edx, [esp + 0x4] // edx = ctx
		lea  ebx, [edx + 0x4] // ebx = &ctx->path
		push ebx              // library path
		call [edx]            // call ctx->LoadLibraryA
		retn 0x4              // return
	}
}

VOID __declspec(naked) get_proc_address_stub()
{
	__asm
	{
		mov  edx, [esp + 0x4] // edx = ctx
		mov  ebx, [edx + 0x4] // ebx = ctx->module
		lea  ecx, [edx + 0x8] // ecx = &ctx->symbol
		push ecx              // push symbol
		push ebx              // push module
		call [edx]            // call ctx->GetProcAddress
		retn 0x4              // return
	}
}

VOID __declspec(naked) unload_library_stub()
{
	__asm
	{
		mov  edx, [esp + 0x4] // edx = ctx
		push [edx + 0x4]      // push module
		call [edx]            // call ctx->FreeLibrary
		retn 0x4              // return
	}
}

#endif
