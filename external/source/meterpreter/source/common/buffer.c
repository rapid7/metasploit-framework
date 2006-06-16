#include "common.h"

/*
 * Parses a file into a buffer
 */
DWORD buffer_from_file(LPCSTR filePath, PUCHAR *buffer, PULONG length)
{
	DWORD res, fileSize = 0, bytesRead = 0, bytesLeft = 0, offset = 0;
	PUCHAR localBuffer = NULL;
	HANDLE h;

	if (buffer)
		*buffer = NULL;
	if (length)
		*length = 0;

	do
	{
		// Try to open the file for reading
		if ((h = CreateFile(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		{
			res = GetLastError();
			break;
		}

		// Get the size, in bytes, of the file
		if (!(fileSize = GetFileSize(h, NULL)))
		{
			res = GetLastError();
			break;
		}

		// Allocate storage for the file data being read in
		if (!(localBuffer = (PUCHAR)malloc(fileSize)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		bytesLeft = fileSize;

		// Keep reading file contents
		while ((bytesLeft) &&
		       (ReadFile(h, localBuffer + offset, bytesLeft, &bytesRead, NULL)))
		{
			bytesLeft -= bytesRead;
			offset    += bytesRead;
		}
		
		res = ERROR_SUCCESS;

	} while (0);

	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);

	if (res == ERROR_SUCCESS)
	{
		if (buffer)
			*buffer = localBuffer;
		if (length)
			*length = offset;
	}

	return res;
}

/*
 * Writes a buffer to a file
 */
DWORD buffer_to_file(LPCSTR filePath, PUCHAR buffer, ULONG length)
{
	DWORD res, offset = 0, bytesLeft = 0, bytesWritten = 0;
	HANDLE h;

	do
	{
		// Try to open the file for writing
		if ((h = CreateFile(filePath, GENERIC_WRITE, 0, NULL, CREATE_NEW,
				FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		{
			res = GetLastError();
			break;
		}

		bytesLeft = length;

		// Keep writing until everything is written
		while ((bytesLeft) &&
		       (WriteFile(h, buffer + offset, bytesLeft, &bytesWritten, NULL)))
		{
			bytesLeft -= bytesWritten;
			offset    += bytesWritten;
		}

		res = ERROR_SUCCESS;

	} while (0);

	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);

	return res;
}
