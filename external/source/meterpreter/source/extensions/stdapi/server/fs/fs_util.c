#include "precomp.h"
#include "fs.h"

/*
 * Returns an expanded file path that must be freed
 */
LPSTR fs_expand_path(LPCSTR regular)
{
#ifdef _WIN32
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
#else /* Hack to make it work with existing code under *nix */
	char *expandedFilePath;
	expandedFilePath = malloc(strlen(regular)+1);
	strcpy(expandedFilePath, regular);
	return expandedFilePath;
#endif
}

/*
 * Fills the platform-independent meterp_stat buf with data from the platform-dependent stat()
 */
int fs_stat(LPCSTR filename, struct meterp_stat *buf) {
	struct stat sbuf;
	int ret;

	ret = stat(filename, &sbuf);

	if (ret == 0) {
		buf->st_dev   = sbuf.st_dev;
		buf->st_ino   = sbuf.st_ino;
		buf->st_mode  = sbuf.st_mode;
		buf->st_nlink = sbuf.st_nlink;
		buf->st_uid   = sbuf.st_uid;
		buf->st_gid   = sbuf.st_gid;
		buf->st_rdev  = sbuf.st_rdev;
		buf->st_size  = sbuf.st_size;
		buf->st_atime = (unsigned long long)sbuf.st_atime;
		buf->st_mtime = (unsigned long long)sbuf.st_mtime;
		buf->st_ctime = (unsigned long long)sbuf.st_ctime;
		return 0;
	} else {
		return ret;
	}
}
