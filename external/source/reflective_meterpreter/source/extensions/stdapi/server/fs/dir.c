#include "precomp.h"
#include <sys/stat.h>

/*
 * Gets the contents of a given directory path and returns the list of file
 * names to the requestor.
 *
 * TLVs:
 *
 * req: TLV_TYPE_DIRECTORY_PATH - The directory that should be listed
 */
DWORD request_fs_ls(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPCSTR directory;
	DWORD result = ERROR_SUCCESS;
	LPSTR expanded = NULL, tempFile = NULL;
	DWORD tempFileSize = 0;
	LPSTR baseDirectory = NULL;
	struct stat buf;

	directory = packet_get_tlv_value_string(packet, TLV_TYPE_DIRECTORY_PATH);

	// Enumerate the directory if one was provided
	if (!directory)
		result = ERROR_INVALID_PARAMETER;
	else
	{
		WIN32_FIND_DATA data;
		BOOLEAN freeDirectory = FALSE;
		HANDLE ctx = NULL;
		LPSTR tempDirectory = (LPSTR)directory;

		// If there is not wildcard mask on the directory, create a version of the
		// directory with a mask appended
		if (!strrchr(directory, '*'))
		{
			if (!(tempDirectory = (LPSTR)malloc(strlen(directory) + 3)))
			{
				result = ERROR_NOT_ENOUGH_MEMORY;
				goto out;
			}

			sprintf(tempDirectory, "%s\\*", directory);	

			// Dupe!
			if (!(baseDirectory = strdup(directory)))
			{
				result = ERROR_NOT_ENOUGH_MEMORY;
				goto out;
			}
		}
		// Otherwise, if it does have an asterisk, we need to scan back and find
		// the base directory.  If there is no slash, it means we're listing the
		// cwd.
		else
		{
			PCHAR slash = strrchr(directory, '\\');

			if (slash)
			{
				*slash = 0;

				if (!(baseDirectory = strdup(directory)))
				{
					result = ERROR_NOT_ENOUGH_MEMORY;
					goto out;
				}

				*slash = '\\';
			}
		}

		// Expand the path
		if (!(expanded = fs_expand_path(tempDirectory)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			goto out;
		}

		// Start the find operation
		ctx = FindFirstFile(expanded, &data);

		do
		{
			DWORD fullSize = (baseDirectory ? strlen(baseDirectory) : 0) + strlen(data.cFileName) + 2;

			// No context?  Sucktastic
			if (ctx == INVALID_HANDLE_VALUE)
			{
				result = GetLastError();
				break;
			}

			// Allocate temporary storage to stat the file
			if ((!tempFile) ||
			    (tempFileSize < fullSize))
			{
				if (tempFile)
					free(tempFile);

				// No memory means we suck a lot like spoon's mom
				if (!(tempFile = (LPSTR)malloc(fullSize)))
				{
					result = ERROR_NOT_ENOUGH_MEMORY;
					break;
				}

				// Update the tempFileSize so that we don't allocate if we don't
				// need to like a true efficient ninja
				tempFileSize = fullSize;
			}

			// Build the full path
			if (baseDirectory)
				sprintf(tempFile, "%s\\%s", baseDirectory, data.cFileName);
			else
				sprintf(tempFile, "%s", data.cFileName);

			// Add the file name to the response
			packet_add_tlv_string(response, TLV_TYPE_FILE_NAME, 
					data.cFileName);
			// Add the full path
			packet_add_tlv_string(response, TLV_TYPE_FILE_PATH,
					tempFile);

			// Stat the file to get more information about it.
			if (stat(tempFile, &buf) >= 0)
				packet_add_tlv_raw(response, TLV_TYPE_STAT_BUF, &buf,
						sizeof(buf));

		} while (FindNextFile(ctx, &data));

		// Clean up resources
		if (freeDirectory)
			free(tempDirectory);
		if (ctx)
			FindClose(ctx);
	}

	if (expanded)
		free(expanded);

out:
	if (baseDirectory)
		free(baseDirectory);

	// Set the result and transmit the response
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}

/*
 * Gets the current working directory
 */
DWORD request_fs_getwd(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD directorySize = 4096, realSize;
	LPSTR directory = NULL;
	DWORD result = ERROR_SUCCESS;

	do
	{
again:
		// Allocate storage for the directory path
		if (!(directory = (LPSTR)malloc(directorySize)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		memset(directory, 0, directorySize);

		if (!(realSize = GetCurrentDirectory(directorySize, directory)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		else if (realSize > directorySize)
		{
			free(directory);

			directorySize = realSize;

			goto again;
		}

		packet_add_tlv_string(response, TLV_TYPE_DIRECTORY_PATH,
				directory);

	} while (0);

	// Set the result and transmit the response
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	if (directory)
		free(directory);

	return ERROR_SUCCESS;
}

/*
 * Changes the working directory of the process
 *
 * TLVs:
 *
 * req: TLV_TYPE_DIRECTORY_PATH - The directory path to change the working
 *                                directory to.
 */
DWORD request_fs_chdir(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPCSTR directory;
	DWORD result = ERROR_SUCCESS;

	directory = packet_get_tlv_value_string(packet, TLV_TYPE_DIRECTORY_PATH);

	if (!directory)
		result = ERROR_INVALID_PARAMETER;
	else if (!SetCurrentDirectory(directory))
		result = GetLastError();

	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}

/*
 * Creates a new directory
 *
 * TLVs:
 *
 * req: TLV_TYPE_DIRECTORY_PATH - The directory path to create.
 */
DWORD request_fs_mkdir(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPCSTR directory;
	DWORD result = ERROR_SUCCESS;

	directory = packet_get_tlv_value_string(packet, TLV_TYPE_DIRECTORY_PATH);

	if (!directory)
		result = ERROR_INVALID_PARAMETER;
	else if (!CreateDirectory(directory, NULL))
		result = GetLastError();

	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}

/*
 * Removes the supplied directory from disk if it's empty
 *
 * TLVs:
 *
 * req: TLV_TYPE_DIRECTORY_PATH - The directory that is to be removed.
 */
DWORD request_fs_delete_dir(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPCSTR directory;
	DWORD result = ERROR_SUCCESS;

	directory = packet_get_tlv_value_string(packet, TLV_TYPE_DIRECTORY_PATH);

	if (!directory)
		result = ERROR_INVALID_PARAMETER;
	else if (!RemoveDirectory(directory))
		result = GetLastError();

	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}
