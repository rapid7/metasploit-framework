#include "precomp.h"

/*
 * Returns an expanded file path that must be freed
 */
LPSTR fs_expand_path(LPCSTR regular)
{
	DWORD expandedFilePathSize = 32768;
	LPSTR expandedFilePath = NULL;

	do
	{
		// Expand the file path
		if (!(expandedFilePath = (LPSTR)malloc(expandedFilePathSize)))
			break;

		// Expand the file path being accessed
		if (!ExpandEnvironmentStrings(regular, expandedFilePath,
				expandedFilePathSize - 1))
		{
			free(expandedFilePath);

			expandedFilePath = 0;

			break;
		}

		expandedFilePath[expandedFilePathSize - 1] = 0;

	} while (0);	

	return expandedFilePath;
}
