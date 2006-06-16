#include "precomp.h"

/*
 * Allocates memory in the context of the supplied process.
 *
 * req: TLV_TYPE_HANDLE          - The process handle to allocate memory within.
 * req: TLV_TYPE_LENGTH          - The amount of memory to allocate.
 * req: TLV_TYPE_ALLOCATION_TYPE - The type of memory to allocate.
 * req: TLV_TYPE_PROTECTION      - The protection flags to allocate the memory with.
 * opt: TLV_TYPE_BASE_ADDRESS    - The address to allocate the memory at.
 */
DWORD request_sys_process_memory_allocate(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	HANDLE handle;
	LPVOID base;
	SIZE_T size;
	DWORD result = ERROR_SUCCESS;
	DWORD alloc, prot;

	// Snag the TLV values
	handle = (HANDLE)packet_get_tlv_value_uint(packet, TLV_TYPE_HANDLE);
	base   = (LPVOID)packet_get_tlv_value_uint(packet, TLV_TYPE_BASE_ADDRESS);
	size   = (SIZE_T)packet_get_tlv_value_uint(packet, TLV_TYPE_LENGTH);
	alloc  = packet_get_tlv_value_uint(packet, TLV_TYPE_ALLOCATION_TYPE);
	prot   = packet_get_tlv_value_uint(packet, TLV_TYPE_PROTECTION);

	// Allocate the memory
	if ((base = VirtualAllocEx(handle, base, size, alloc, prot)))
		packet_add_tlv_uint(response, TLV_TYPE_BASE_ADDRESS, (DWORD)base);
	else
		result = GetLastError();

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Free memory in the context of the supplied process
 *
 * req: TLV_TYPE_HANDLE       - The handle to free memory within.
 * req: TLV_TYPE_BASE_ADDRESS - The base address of the memory to free.
 * opt: TLV_TYPE_LENGTH       - The size, in bytes, to free.
 */
DWORD request_sys_process_memory_free(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	HANDLE handle;
	SIZE_T size;
	LPVOID base;
	DWORD result = ERROR_SUCCESS;

	handle = (HANDLE)packet_get_tlv_value_uint(packet, TLV_TYPE_HANDLE);
	base   = (LPVOID)packet_get_tlv_value_uint(packet, TLV_TYPE_BASE_ADDRESS);
	size   = packet_get_tlv_value_uint(packet, TLV_TYPE_LENGTH);

	// Free the memory
	if (!VirtualFreeEx(handle, base, size, MEM_RELEASE))
		result = GetLastError();

	// Transmit the response
	packet_transmit_response(result, remote, packet);

	return ERROR_SUCCESS;
}

/*
 * Read memory from the context of the supplied process at a given address for a
 * given length
 *
 * req: TLV_TYPE_HANDLE       - The handle of the process to read from.
 * req: TLV_TYPE_BASE_ADDRESS - The address to read from.
 * req: TLV_TYPE_LENGTH       - The number of bytes to read.
 */
DWORD request_sys_process_memory_read(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPVOID buffer = NULL;
	HANDLE handle;
	SIZE_T size;
	LPVOID base;
	DWORD bytesRead = 0;
	DWORD result = ERROR_SUCCESS;

	handle = (HANDLE)packet_get_tlv_value_uint(packet, TLV_TYPE_HANDLE);
	base   = (LPVOID)packet_get_tlv_value_uint(packet, TLV_TYPE_BASE_ADDRESS);
	size   = packet_get_tlv_value_uint(packet, TLV_TYPE_LENGTH);

	do
	{
		// No handle, base, or size supplied?
		if ((!handle) ||
		    (!base) ||
		    (!size))
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Allocate storage for to read into
		if (!(buffer = malloc(size)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Read the memory from the process...break out on failure
		if ((!ReadProcessMemory(handle, base, buffer, size, &bytesRead)) &&
		    (GetLastError() != ERROR_PARTIAL_COPY))
		{
			result = GetLastError();
			break;
		}

		// Add the raw buffer to the response
		packet_add_tlv_raw(response, TLV_TYPE_PROCESS_MEMORY, buffer,
				bytesRead);

	} while (0);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	// Free the temporary storage
	if (buffer)
		free(buffer);

	return ERROR_SUCCESS;
}

/*
 * Read memory from the context of the supplied process at a given address for a
 * given length
 *
 * req: TLV_TYPE_HANDLE         - The handle of the process to read from.
 * req: TLV_TYPE_BASE_ADDRESS   - The address to read from.
 * req: TLV_TYPE_PROCESS_MEMORY - The raw memory to write to the address.
 */
DWORD request_sys_process_memory_write(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	HANDLE handle;
	LPVOID base;
	DWORD result = ERROR_SUCCESS;
	DWORD written = 0;
	Tlv data;

	handle = (HANDLE)packet_get_tlv_value_uint(packet, TLV_TYPE_HANDLE);
	base   = (LPVOID)packet_get_tlv_value_uint(packet, TLV_TYPE_BASE_ADDRESS);

	do
	{
		// Invalid handle, base, or data?
		if ((!handle) ||
		    (!base) ||
		    (packet_get_tlv(packet, TLV_TYPE_PROCESS_MEMORY, &data)) != ERROR_SUCCESS)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Write the memory
		if ((!WriteProcessMemory(handle, base, data.buffer, data.header.length, 
				&written)) &&
		    (GetLastError() != ERROR_PARTIAL_COPY))
		{
			result = GetLastError();
			break;
		}

		// Set the number of bytes actually written on the response
		packet_add_tlv_uint(response, TLV_TYPE_LENGTH, written);

	} while (0);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Queries an address region for its attributes, such as size and protection
 *
 * req: TLV_TYPE_HANDLE       - The process handle to operate on.
 * req: TLV_TYPE_BASE_ADDRESS - The address to query the attributes of.
 */
DWORD request_sys_process_memory_query(Remote *remote, Packet *packet)
{
	MEMORY_BASIC_INFORMATION info;
	Packet *response = packet_create_response(packet);
	HANDLE handle;
	LPVOID base;
	DWORD result = ERROR_SUCCESS;
	DWORD size = 0;

	handle = (HANDLE)packet_get_tlv_value_uint(packet, TLV_TYPE_HANDLE);
	base   = (LPVOID)packet_get_tlv_value_uint(packet, TLV_TYPE_BASE_ADDRESS);

	// Zero the info buffer
	memset(&info, 0, sizeof(info));

	do
	{
		// Validate parameters
		if (!handle)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// No bytes returned?  Suck.
		if (!(size = VirtualQueryEx(handle, base, &info, sizeof(info))))
		{
			result = GetLastError();
			break;
		}

		// Pass the parameters back to the requestor
		packet_add_tlv_uint(response, TLV_TYPE_BASE_ADDRESS,
				(DWORD)info.BaseAddress);
		packet_add_tlv_uint(response, TLV_TYPE_ALLOC_BASE_ADDRESS,
				(DWORD)info.AllocationBase);
		packet_add_tlv_uint(response, TLV_TYPE_ALLOC_PROTECTION,
				info.AllocationProtect);
		packet_add_tlv_uint(response, TLV_TYPE_LENGTH,
				info.RegionSize);
		packet_add_tlv_uint(response, TLV_TYPE_MEMORY_STATE,
				info.State);
		packet_add_tlv_uint(response, TLV_TYPE_PROTECTION,
				info.Protect);
		packet_add_tlv_uint(response, TLV_TYPE_MEMORY_TYPE,
				info.Type);

	} while (0);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Changes the protection flags on one or more pages
 *
 * req: TLV_TYPE_HANDLE       - The process handle to operate on
 * req: TLV_TYPE_BASE_ADDRESS - The base address to re-protect
 * req: TLV_TYPE_LENGTH       - The length of the region to re-protect
 * req: TLV_TYPE_PROTECTION   - The new protection mask
 */
DWORD request_sys_process_memory_protect(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	HANDLE handle;
	LPVOID base;
	SIZE_T size;
	DWORD prot, old;
	DWORD result = ERROR_SUCCESS;

	handle = (HANDLE)packet_get_tlv_value_uint(packet, TLV_TYPE_HANDLE);
	base   = (LPVOID)packet_get_tlv_value_uint(packet, TLV_TYPE_BASE_ADDRESS);
	size   = packet_get_tlv_value_uint(packet, TLV_TYPE_LENGTH);
	prot   = packet_get_tlv_value_uint(packet, TLV_TYPE_PROTECTION);

	do
	{
		// Validate parameters
		if ((!handle) ||
		    (!base) ||
		    (!size))
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Change the protection mask
		if (!VirtualProtectEx(handle, base, size, prot, &old))
		{
			result = GetLastError();
			break;
		}

		// Return the old protection mask to the requestor
		packet_add_tlv_uint(response, TLV_TYPE_PROTECTION, old);

	} while (0);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Lock a region of memory in physical memory so that it cannot be swapped 
 * out.
 *
 * req: TLV_TYPE_BASE_ADDRESS - The base address to lock
 * req: TLV_TYPE_LENGTH       - The size of the region to lock
 */
DWORD request_sys_process_memory_lock(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPVOID base;
	SIZE_T size;
	DWORD result = ERROR_SUCCESS;

	base = (LPVOID)packet_get_tlv_value_uint(packet, TLV_TYPE_BASE_ADDRESS);
	size = packet_get_tlv_value_uint(packet, TLV_TYPE_LENGTH);

	if (!VirtualLock(base, size))
		result = GetLastError();

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Unlock a region so that it can be swapped to disk.
 *
 * req: TLV_TYPE_BASE_ADDRESS - The base address to lock
 * req: TLV_TYPE_LENGTH       - The size of the region to lock
 */
DWORD request_sys_process_memory_unlock(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPVOID base;
	SIZE_T size;
	DWORD result = ERROR_SUCCESS;

	base = (LPVOID)packet_get_tlv_value_uint(packet, TLV_TYPE_BASE_ADDRESS);
	size = packet_get_tlv_value_uint(packet, TLV_TYPE_LENGTH);

	if (!VirtualUnlock(base, size))
		result = GetLastError();

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}
