#include "precomp.h"
#include <sys/stat.h>

#ifndef _WIN32
 #include <dirent.h>
#endif

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
#ifdef _WIN32
		WIN32_FIND_DATA data;
		HANDLE ctx = NULL;
#else
		DIR *ctx;
		struct dirent *data;
#endif
		BOOLEAN freeDirectory = FALSE;
		LPSTR tempDirectory = (LPSTR)directory;

#ifdef _WIN32
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
			if (!(baseDirectory = _strdup(directory)))
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

				if (!(baseDirectory = _strdup(directory)))
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

 #define DF_NAME data.cFileName
#else
		expanded = 0;
		ctx = opendir(tempDirectory);
		if(ctx == NULL)
		{
		  result = errno;
		  goto out;
		}
		data = readdir(ctx);
	      
 #define DF_NAME data->d_name

#endif

		do
		{
			DWORD fullSize = (baseDirectory ? strlen(baseDirectory) : 0) + strlen(DF_NAME) + 2;

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
				sprintf(tempFile, "%s\\%s", baseDirectory, DF_NAME);
			else
				sprintf(tempFile, "%s", DF_NAME);

			// Add the file name to the response
			packet_add_tlv_string(response, TLV_TYPE_FILE_NAME, 
					DF_NAME);
			// Add the full path
			packet_add_tlv_string(response, TLV_TYPE_FILE_PATH,
					tempFile);

			// Stat the file to get more information about it.
			if (stat(tempFile, &buf) >= 0)
				packet_add_tlv_raw(response, TLV_TYPE_STAT_BUF, &buf,
						sizeof(buf));

#ifdef _WIN32
		} while (FindNextFile(ctx, &data));
#else
	        } while (data = readdir(ctx));
#endif
#undef DF_NAME

		// Clean up resources
		if (freeDirectory)
			free(tempDirectory);
		if (ctx)
#ifdef _WIN32
			FindClose(ctx);
#else
			closedir(ctx);
#endif
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

#ifdef _WIN32
		if (!(realSize = GetCurrentDirectory(directorySize, directory)))
#else
		if (!(realSize = getcwd(directory, directorySize)))
#endif
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
#ifdef _WIN32
	else if (!SetCurrentDirectory(directory))
#else
	else if (!chdir(directory))
#endif
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
#ifdef _WIN32
	else if (!CreateDirectory(directory, NULL))
#else
	else if (!mkdir(directory, 777))
#endif
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
#ifdef _WIN32
	else if (!RemoveDirectory(directory))
#else
	else if (!rmdir(directory))
#endif
		result = GetLastError();

	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	return ERROR_SUCCESS;
}
