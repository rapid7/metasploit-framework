#include "precomp.h"
#include <shlwapi.h>

DWORD request_registry_create_key(Remote *remote, Packet *packet);

/*
 * Opens a registry key and returns the associated HKEY to the caller if the
 * operation succeeds.  Right now this is just a wrapper around create_key
 *
 * TLVs:
 *
 * req: TLV_TYPE_ROOT_KEY   - The root key
 * req: TLV_TYPE_BASE_KEY   - The base key
 * opt: TLV_TYPE_PERMISSION - Permissions with which to open the key
 */
DWORD request_registry_open_key(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPCTSTR baseKey = NULL;
	HKEY rootKey = NULL, resKey;
	DWORD permission;
	DWORD result;

	rootKey    = (HKEY)packet_get_tlv_value_uint(packet, TLV_TYPE_ROOT_KEY);
	baseKey    = packet_get_tlv_value_string(packet, TLV_TYPE_BASE_KEY);
	permission = packet_get_tlv_value_uint(packet, TLV_TYPE_PERMISSION);

	// Validate the parameters and then attempt to create the key
	if ((!rootKey) || (!baseKey))
		result = ERROR_INVALID_PARAMETER;
	else
	{
		if (!permission)
			permission = KEY_ALL_ACCESS;
		
		result = RegOpenKeyEx(rootKey, baseKey, 0, permission, &resKey);
	}

	// Add the HKEY if we succeeded, but always return a result
	if (result == ERROR_SUCCESS)
		packet_add_tlv_uint(response, TLV_TYPE_HKEY, (DWORD)resKey);

	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}

/*
 * Creates a registry key and returns the associated HKEY to the caller if the
 * operation succeeds.
 *
 * TLVs:
 *
 * req: TLV_TYPE_ROOT_KEY   - The root key
 * req: TLV_TYPE_BASE_KEY   - The base key
 * opt: TLV_TYPE_PERMISSION - Permissions with which to create the key
 */
DWORD request_registry_create_key(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPCTSTR baseKey = NULL;
	HKEY rootKey = NULL, resKey;
	DWORD permission;
	DWORD result;

	rootKey    = (HKEY)packet_get_tlv_value_uint(packet, TLV_TYPE_ROOT_KEY);
	baseKey    = packet_get_tlv_value_string(packet, TLV_TYPE_BASE_KEY);
	permission = packet_get_tlv_value_uint(packet, TLV_TYPE_PERMISSION);

	// Validate the parameters and then attempt to create the key
	if ((!rootKey) || (!baseKey))
		result = ERROR_INVALID_PARAMETER;
	else
	{
		if (!permission)
			permission = KEY_ALL_ACCESS;
		
		result = RegCreateKeyEx(rootKey, baseKey, 0, NULL, 0,
				permission, NULL, &resKey, NULL);
	}

	// Add the HKEY if we succeeded, but always return a result
	if (result == ERROR_SUCCESS)
		packet_add_tlv_uint(response, TLV_TYPE_HKEY, (DWORD)resKey);

	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}

/*
 * Enumerates a supplied registry key and returns a list of all the direct
 * sub-keys.
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY - The HKEY that is to be enumerated
 */
DWORD request_registry_enum_key(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result;
	HKEY hkey = (HKEY)packet_get_tlv_value_uint(packet, TLV_TYPE_HKEY);

	if (!hkey)
		result = ERROR_INVALID_PARAMETER;
	else
	{
		DWORD nameSize = 4096;
		DWORD index = 0;
		DWORD tries = 0;
		LPSTR name = NULL;

		// Keep looping until we reach the end
		while (1)
		{
			// If the name storage is NULL, allocate it
			if (!name)
				name = (LPSTR)malloc(nameSize);

			result = RegEnumKey(hkey, index, name, nameSize);

			// If we need more room...
			if (result == ERROR_MORE_DATA)
			{
				if (tries > 3)
					break;

				free(name);

				nameSize *= 2;
				name      = NULL;

				tries++;

				continue;
			}
			// If we've reached the end of our road...
			else if (result == ERROR_NO_MORE_ITEMS)
			{
				result = ERROR_SUCCESS;
				break;
			}
			// If we flunked out of school...
			else if (result != ERROR_SUCCESS)
				break;

			// Reset tries
			tries = 0;

			// Add the registry key name
			packet_add_tlv_string(response, TLV_TYPE_KEY_NAME,
					name);

			// Next entry
			index++;
		}
	}

	// Set the result and transmit the response
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}

/*
 * Removes a registry key with the supplied root and base key information.
 *
 * TLVs:
 *
 * req: TLV_TYPE_ROOT_KEY - The root key handle.
 * req: TLV_TYPE_BASE_KEY - The base key name.
 * opt: TLV_TYPE_FLAGS    - Zero or more flags that control how the key is
 *                          deleted.
 */
DWORD request_registry_delete_key(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPCSTR baseKey = NULL;
	DWORD result = ERROR_SUCCESS;
	DWORD flags = 0;
	HKEY rootKey = NULL;

	rootKey = (HKEY)packet_get_tlv_value_uint(packet, TLV_TYPE_ROOT_KEY);
	baseKey = packet_get_tlv_value_string(packet, TLV_TYPE_BASE_KEY);
	flags   = packet_get_tlv_value_uint(packet, TLV_TYPE_FLAGS);

	if ((!rootKey) || 
	    (!baseKey))
		result = ERROR_INVALID_PARAMETER;
	else
	{
		if (flags & DELETE_KEY_FLAG_RECURSIVE)
			result = SHDeleteKey(rootKey, baseKey);
		else
			result = RegDeleteKey(rootKey, baseKey);
	}

	// Set the result and send the response
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}

/*
 * Closes the supplied HKEY
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY - The HKEY that is to be closed
 */
DWORD request_registry_close_key(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result;
	HKEY hkey = (HKEY)packet_get_tlv_value_uint(packet, TLV_TYPE_HKEY);

	// No param?  No love.
	if (!hkey)
		result = ERROR_INVALID_PARAMETER;
	else
		result = RegCloseKey(hkey);

	// Set the result and send the response
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}

/*
 * Sets a registry value with the supplied data for a given HKEY.
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY       - The HKEY to set the value on
 * req: TLV_TYPE_VALUE_NAME - The name of the value to set
 * req: TLV_TYPE_VALUE_TYPE - The type of the value to set
 * req: TLV_TYPE_VALUE_DATA - The data to set the value to
 */
DWORD request_registry_set_value(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPCSTR valueName = NULL;
	DWORD valueType = 0;
	DWORD result = ERROR_SUCCESS;
	HKEY hkey = NULL;
	Tlv valueData;

	// Acquire the standard TLVs
	hkey      = (HKEY)packet_get_tlv_value_uint(packet, TLV_TYPE_HKEY);
	valueName = packet_get_tlv_value_string(packet, TLV_TYPE_VALUE_NAME);
	valueType = packet_get_tlv_value_uint(packet, TLV_TYPE_VALUE_TYPE);
	
	do
	{
		// Get the value data TLV
		if (packet_get_tlv(packet, TLV_TYPE_VALUE_DATA, 
				&valueData) != ERROR_SUCCESS)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Now let's rock this shit!
		result = RegSetValueEx(hkey, valueName, 0, valueType, 
				valueData.buffer, valueData.header.length);

	} while (0);

	// Populate the result code
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	// Transmit the response
	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}

/*
 * Queries a registry value's type and data for a given HKEY.
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY       - The HKEY to query the value on
 * req: TLV_TYPE_VALUE_NAME - The name of the value to query
 */
DWORD request_registry_query_value(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPCSTR valueName = NULL;
	LPBYTE valueData = NULL;
	DWORD valueDataSize = 4096;
	DWORD result = ERROR_SUCCESS;
	DWORD valueType = 0;
	HKEY hkey = NULL;

	// Acquire the standard TLVs
	hkey      = (HKEY)packet_get_tlv_value_uint(packet, TLV_TYPE_HKEY);
	valueName = packet_get_tlv_value_string(packet, TLV_TYPE_VALUE_NAME);

	do
	{
		// Get the size of the value data
		if ((result = RegQueryValueEx(hkey, valueName, 0, NULL, NULL, 
				&valueDataSize)) != ERROR_SUCCESS)
			break;

		// Allocate storage for the value data
		if (!(valueData = (LPBYTE)malloc(valueDataSize)))
			continue;

		// Query the value's information
		if ((result = RegQueryValueEx(hkey, valueName, 0, &valueType, valueData,
				&valueDataSize)) != ERROR_SUCCESS)
			break;

		// Add the information about the value to the response
		packet_add_tlv_uint(response, TLV_TYPE_VALUE_TYPE, valueType);

		switch (valueType)
		{
			case REG_SZ:
				packet_add_tlv_string(response, TLV_TYPE_VALUE_DATA, 
						(LPCSTR)valueData);
				break;
			case REG_DWORD:
				packet_add_tlv_uint(response, TLV_TYPE_VALUE_DATA,
						*(LPDWORD)valueData);
				break;
			default:
				packet_add_tlv_raw(response, TLV_TYPE_VALUE_DATA,
						valueData, valueDataSize);
				break;
		}

	} while (0);

	// Populate the result code
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	// Transmit the response
	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}

/*
 * Enumerates all of the values at the supplied HKEY.
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY - The HKEY that will have its values enumerated.
 */
DWORD request_registry_enum_value(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result;
	HKEY hkey = (HKEY)packet_get_tlv_value_uint(packet, TLV_TYPE_HKEY);

	if (!hkey)
		result = ERROR_INVALID_PARAMETER;
	else
	{
		DWORD nameSize = 4096, realSize = 4096;
		DWORD index = 0;
		DWORD tries = 0;
		LPSTR name = NULL;

		// Keep looping until we reach the end
		while (1)
		{
			// If the name storage is NULL, allocate it
			if (!name)
				name = (LPSTR)malloc(nameSize);

			result = RegEnumValue(hkey, index, name, &nameSize,
					NULL, NULL, NULL, NULL);

			// Reset the real size
			nameSize = realSize;

			// If we need more room...
			if (result == ERROR_MORE_DATA)
			{
				if (tries > 3)
					break;

				free(name);

				realSize = nameSize *= 3;
				name     = NULL;

				tries++;

				continue;
			}
			// If we've reached the end of our road...
			else if (result == ERROR_NO_MORE_ITEMS)
			{
				result = ERROR_SUCCESS;
				break;
			}
			// If we flunked out of school...
			else if (result != ERROR_SUCCESS)
				break;

			// Reset tries
			tries = 0;

			// Add the registry value name
			packet_add_tlv_string(response, TLV_TYPE_VALUE_NAME,
					name);

			// Next entry
			index++;
		}
	}

	// Set the result and transmit the response
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}

/*
 * Deletes a registry value from the supplied registry key
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY       - The HKEY from which to delete the value
 * req: TLV_TYPE_VALUE_NAME = The name of the value to delete
 */
DWORD request_registry_delete_value(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPCSTR valueName = NULL;
	DWORD result = ERROR_SUCCESS;
	HKEY hkey = NULL;

	hkey      = (HKEY)packet_get_tlv_value_uint(packet, TLV_TYPE_HKEY);
	valueName = (LPCSTR)packet_get_tlv_value_string(packet, TLV_TYPE_VALUE_NAME);

	// Check for invalid parameters
	if ((!hkey) || 
	    (!valueName))
		result = ERROR_INVALID_PARAMETER;
	else
		result = RegDeleteValue(hkey, valueName);

	// Set the result and send the response
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}

/*
 * Queries a registry class for a given HKEY.
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY       - The HKEY to query the class on
 */
DWORD request_registry_query_class(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPCSTR valueName = NULL;
	BYTE valueData[4096];
	DWORD valueDataSize = 4096;
	DWORD result = ERROR_SUCCESS;
	DWORD valueType = 0;
	HKEY hkey = NULL;

	// Acquire the standard TLVs
	hkey      = (HKEY)packet_get_tlv_value_uint(packet, TLV_TYPE_HKEY);

	do
	{
		// Get the size of the value data
		if ((result = RegQueryInfoKey(hkey, valueData, &valueDataSize, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) != ERROR_SUCCESS)
			break;

		packet_add_tlv_string(response, TLV_TYPE_VALUE_DATA, (LPCSTR)valueData);

	} while (0);

	// Populate the result code
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	// Transmit the response
	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}
