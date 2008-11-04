#include "precomp.h"

HMODULE hookLibrary = NULL;

/*
 * Extract and load the hook library
 */
DWORD extract_hook_library()
{
	HGLOBAL global = NULL;
	HRSRC fileHandle = NULL;
	LPVOID raw = NULL;
	DWORD rawSize = 0;
	DWORD result = ERROR_SUCCESS;
	CHAR tempFile[1024];
	FILE *fd = NULL;

	memset(tempFile, 0, sizeof(tempFile));

	do
	{
		ExpandEnvironmentStrings("%TEMP%\\hook.dll", tempFile, 
				sizeof(tempFile) - 1);

		fileHandle = FindResource( hAppInstance, 
				MAKEINTRESOURCE(IDR_HOOK_DLL), "IMG");

		if (!fileHandle)
		{
			result = GetLastError();
			break;
		}

		global  = LoadResource( hAppInstance, fileHandle );
		raw     = LockResource(global);
		rawSize = SizeofResource( hAppInstance, fileHandle );

		DeleteFile(tempFile);

		// Write the file to disk
		if (GetFileAttributes(tempFile) == INVALID_FILE_ATTRIBUTES)
		{
			if ((fd = fopen(tempFile, "wb")))
			{
				fwrite(raw, 1, rawSize, fd);

				fclose(fd);
			}
			else
				result = GetLastError();
		}

		// Try to load the library
		if (!(hookLibrary = LoadLibrary(tempFile)))
		{
			result = GetLastError();
			break;
		}

	} while (0);

	return result;
}
