/* skape <mmiller@hick.org */

/*
 * dumps all the mapped memory segments in a running process
 */
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#define PAGE_SIZE 4096

typedef struct _MemoryRange
{

	char                *base;
	unsigned long       length;
	char                *file;
	struct _MemoryRange *next;

} MemoryRange;

BOOL createDumpDirectory(char *path);
DWORD dumpSegments(HANDLE process, const char *dumpDirectory);

int main(int argc, char **argv)
{
	char *dumpDirectory = NULL;
	HANDLE process = NULL;
	DWORD pid = 0,
		segments = 0;
	int res = 1;

	do
	{
		// Validate arguments
		if ((argc == 1) ||
		    (!(pid = atoi(argv[1]))))
		{
			printf("Usage: %s pid [dump directory]\n", argv[0]);
			break;
		}

		// If a dump directory is specified, use it, otherwise default 
		// to the pid.
		if (argc >= 3)
			dumpDirectory = argv[2];
		else
			dumpDirectory = argv[1];

		// Create the dump directory (make sure it exists)
		printf("[*] Creating dump directory...%s\n", dumpDirectory);

		if (!createDumpDirectory(dumpDirectory))
		{
			printf("[-] Creation failed, %.8x.\n", GetLastError());
			break;
		}

		// Attach to the process
		printf("[*] Attaching to %lu...\n", pid);

		if (!(process = OpenProcess(PROCESS_VM_READ, FALSE, pid)))
		{
			printf("[-] Attach failed, %.8x.\n", GetLastError());
			break;
		}

		// Dump segments
		printf("[*] Dumping segments...\n");

		if (!(segments = dumpSegments(process, dumpDirectory)))
		{
			printf("[-] Dump failed, %.8x.\n", GetLastError());
			break;
		}

		printf("[*] Dump completed successfully, %lu segments.\n", segments);

		res = 0;
		
	} while (0);

	if (process)
		CloseHandle(process);

	return res;
}

/*
 * Create the directory specified by path, insuring that 
 * all parents exist along the way.
 *
 * Just like MakeSureDirectoryPathExists, but portable.
 */
BOOL createDumpDirectory(char *path)
{
	char *slash = path;
	BOOL res = TRUE;

	do
	{
		slash = strchr(slash, '\\');

		if (slash)
			*slash = 0;

		if (!CreateDirectory(path, NULL))
		{
			if ((GetLastError() != ERROR_FILE_EXISTS) &&
			    (GetLastError() != ERROR_ALREADY_EXISTS))
			{
				res = FALSE;
				break;
			}
		}

		if (slash)
			*slash++ = '\\';

	} while (slash);

	return res;
}

/*
 * Dump all mapped segments into the dump directory, one file per
 * each segment.  Finally, create an index of all segments.
 */
DWORD dumpSegments(HANDLE process, const char *dumpDirectory)
{
	MemoryRange *ranges = NULL, 
		*prevRange = NULL,
		*currentRange = NULL;
	char pbuf[PAGE_SIZE],
		rangeFileName[256];
	DWORD segments = 0, 
		bytesRead = 0,
		cycles = 0;
	char *current = NULL;
	FILE *rangeFd = NULL;

	// Enumerate page by page
	for (current = 0;
	     ;
	     current += PAGE_SIZE, cycles++)

	{
		// If we've wrapped, break out.
		if (!current && cycles)
			break;

		// Invalid page? Cool, reset current range.
		if (!ReadProcessMemory(process, current, pbuf, 
			sizeof(pbuf), &bytesRead))
		{
			if (currentRange)
			{
				prevRange    = currentRange;
				currentRange = NULL;
			}

			if (rangeFd)
			{
				fclose(rangeFd);

				rangeFd = NULL;
			}

			continue;
		}

		// If the current range is not valid, we've hit a new range.
		if (!currentRange)
		{
			// Try to allocate storage for it, if we fail, bust out.
			if (!(currentRange = (MemoryRange *)malloc(sizeof(MemoryRange))))
			{
				printf("[-] Allocation failure\n");
	
				segments = 0;
	
				break;
			}

			currentRange->base   = current;
			currentRange->length = 0;
			currentRange->next   = NULL;

			if (prevRange)
				prevRange->next = currentRange;
			else
				ranges = currentRange;

			// Finally, open a file for this range
			_snprintf(rangeFileName, sizeof(rangeFileName) - 1, "%s\\%.8x.rng",
				dumpDirectory, current);

			if (!(rangeFd = fopen(rangeFileName, "wb")))
			{
				printf("[-] Could not open range file: %s\n", rangeFileName);

				segments = 0;

				break;
			}

			// Duplicate the file name for ease of access later
			currentRange->file = strdup(rangeFileName);

			// Increment the number of total segments
			segments++;
		}

		// Write to the range file
		fwrite(pbuf, 1, bytesRead, rangeFd);

		currentRange->length += bytesRead;
	}

	// Now that all the ranges are mapped, dump them to an index file
	_snprintf(rangeFileName, sizeof(rangeFileName) - 1, "%s\\index.rng",
		dumpDirectory);

	if ((rangeFd = fopen(rangeFileName, "w")))
	{
		char cwd[MAX_PATH];

		GetCurrentDirectory(sizeof(cwd), cwd);

		// Enumerate all of the ranges, dumping them into the index file
		for (currentRange = ranges;
		     currentRange;
		     currentRange = currentRange->next)
		{
			fprintf(rangeFd, "%.8x;%lu;%s\\%s\n", 
				currentRange->base, currentRange->length, cwd,
				currentRange->file ? currentRange->file : "");
		}

		fclose(rangeFd);
	}
	else
		segments = 0;
	
	return segments;
}
