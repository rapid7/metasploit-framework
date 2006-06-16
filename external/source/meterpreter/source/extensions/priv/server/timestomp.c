/*	
	Copyright (C) 2005 Vincent Liu

	This file is part of Timestomp

	Timestomp is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

// #######################################################################
// ############ HEADER FILES
// #######################################################################
#include <windows.h>
#include <stdio.h>

// #######################################################################
// ############ DEFINITIONS
// #######################################################################
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define FILE_NON_DIRECTORY_FILE 0x00000040

typedef LONG NTSTATUS;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
    FileBasicInformation = 4,           
    FileStandardInformation = 5,        
    FilePositionInformation = 14,        
    FileEndOfFileInformation = 20,       
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_BASIC_INFORMATION {                    
    LARGE_INTEGER CreationTime;							// Created             
    LARGE_INTEGER LastAccessTime;                       // Accessed    
    LARGE_INTEGER LastWriteTime;                        // Modifed
    LARGE_INTEGER ChangeTime;                           // Entry Modified
    ULONG FileAttributes;                                   
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef NTSTATUS (WINAPI *pNtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS (WINAPI *pNtSetInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);

DWORD ParseDateTimeInput(char *inputstring, SYSTEMTIME *systemtime);
HANDLE RetrieveFileBasicInformation(char *filename, FILE_BASIC_INFORMATION *fbi);
DWORD ConvertLocalTimeToLargeInteger(SYSTEMTIME localsystemtime, LARGE_INTEGER *largeinteger);
DWORD ConvertLargeIntegerToLocalTime(SYSTEMTIME *localsystemtime, LARGE_INTEGER largeinteger);
DWORD SetFileMACE(HANDLE file, FILE_BASIC_INFORMATION fbi);
DWORD InputHandler(int argc, char **argv);
void PrintSystemTime(SYSTEMTIME systime);
void Usage();


// #######################################################################
// ############ FUNCTIONS
// #######################################################################

/* returns 0 on error, 1 on success. this function set the MACE values based on 
the input from the FILE_BASIC_INFORMATION structure */
DWORD SetFileMACE(HANDLE file, FILE_BASIC_INFORMATION fbi) {

	HANDLE ntdll = NULL;
	IO_STATUS_BLOCK iostatus;
	pNtSetInformationFile NtSetInformationFile = NULL;

	ntdll = LoadLibrary("ntdll.dll");
	if (ntdll == NULL) {
		return 0;
	}

	NtSetInformationFile = (pNtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");
	if (NtSetInformationFile == NULL) {
		return 0;
	}

	if (NtSetInformationFile(file, &iostatus, &fbi, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation) < 0) {
		return 0;
	}
	
	/* clean up */
	FreeLibrary(ntdll);

	return 1;
}

/* returns the handle on success or NULL on failure. this function opens a file and returns
the FILE_BASIC_INFORMATION on it. */
HANDLE RetrieveFileBasicInformation(char *filename, FILE_BASIC_INFORMATION *fbi) {
	
	HANDLE file = NULL;
	HANDLE ntdll = NULL;
	pNtQueryInformationFile NtQueryInformationFile = NULL;
	IO_STATUS_BLOCK iostatus;
	
	file = CreateFile(filename, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		return 0;
	}

	/* load ntdll and retrieve function pointer */
	ntdll = LoadLibrary("ntdll.dll");
	if (ntdll == NULL) {
		CloseHandle(file);
		return 0;
	}

	/* retrieve current timestamps including file attributes which we want to preserve */
	NtQueryInformationFile = (pNtQueryInformationFile)GetProcAddress(ntdll, "NtQueryInformationFile");
	if (NtQueryInformationFile == NULL) {
		CloseHandle(file);
		return 0;
	}

	/* obtain the current file information including attributes */
	if (NtQueryInformationFile(file, &iostatus, fbi, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation) < 0) {
		CloseHandle(file);
		return 0;
	}

	/* clean up */
	FreeLibrary(ntdll);

	return file;
}

// returns 0 on error, 1 on success. this function converts a SYSTEMTIME structure to a LARGE_INTEGER
DWORD ConvertLocalTimeToLargeInteger(SYSTEMTIME localsystemtime, LARGE_INTEGER *largeinteger) {

	// the local time is stored in the system time structure argument which should be from the user
	// input. the user inputs the times in local time which is then converted to utc system time because
	// ntfs stores all timestamps in utc, which is then converted to a large integer
	
	// MSDN recommends converting SYSTEMTIME to FILETIME via SystemTimeToFileTime() and
	// then copying the values in FILETIME to a ULARGE_INTEGER structure.

	FILETIME filetime;
	FILETIME utcfiletime;
	DWORD result = 0;

	/*
	result = GetTimeZoneInformation(&timezone);
	if (result == TIME_ZONE_ID_INVALID) {
	printf("Error: Could not obtain the local time zone information.\n");
		return 0;
	}
	
	if (TzSpecificLocalTimeToSystemTime(&timezone, &localsystemtime, &utcsystemtime) == 0) {
		printf("Error: Couldn't convert local time to UTC time.\n");
		return 0;
	}
	*/

	// convert the SYSTEMTIME structure to a FILETIME structure
    if (SystemTimeToFileTime(&localsystemtime, &filetime) == 0) {
		return 0;
	}

	// convert the local file time to UTC
	if (LocalFileTimeToFileTime(&filetime, &utcfiletime) == 0) {
		return 0;
	}

	/* copying lowpart from a DWORD to DWORD, and copying highpart from a DWORD to a LONG.
	potential data loss of upper values 2^16, but acceptable bc we wouldn't be able to set 
	this high even if we wanted to because NtSetInformationFile() takes a max of what's
	provided in LARGE_INTEGER */
	largeinteger->LowPart = utcfiletime.dwLowDateTime;
	largeinteger->HighPart = utcfiletime.dwHighDateTime;	

	return 1;
}

/* returns 0 on error, 1 on success. this function converts a LARGE_INTEGER to a SYSTEMTIME structure */
DWORD ConvertLargeIntegerToLocalTime(SYSTEMTIME *localsystemtime, LARGE_INTEGER largeinteger) {

	FILETIME filetime;
	FILETIME localfiletime;
	DWORD result = 0;

	filetime.dwLowDateTime = largeinteger.LowPart;
	filetime.dwHighDateTime = largeinteger.HighPart;

	if (FileTimeToLocalFileTime(&filetime, &localfiletime) == 0) {
		return 0;
	}

    if (FileTimeToSystemTime(&localfiletime, localsystemtime) == 0) {
		return 0;
	}
/*
	result = GetTimeZoneInformation(&timezone);
	if (result == TIME_ZONE_ID_INVALID) {
	printf("Error: Could not obtain the local time zone information.\n");
		return 0;
	}
	
	if (SystemTimeToTzSpecificLocalTime(&timezone, &utcsystemtime, localsystemtime) == 0) {
		printf("Error: Couldn't convert UTC time to local time.\n");
		return 0;
	}
*/
	return 1;
}

/* returns 1 on success or 0 on failure. this function converts an input string into a SYSTEMTIME structure */
DWORD ParseDateTimeInput(char *inputstring, SYSTEMTIME *systemtime) {

	char day[10];
	char daynight[3];

	if (sscanf(inputstring, "%9s %hu/%hu/%hu %hu:%hu:%hu %2s", day, &systemtime->wMonth, &systemtime->wDay, &systemtime->wYear, &systemtime->wHour, &systemtime->wMinute, &systemtime->wSecond, daynight) == 0) {
		return 0;
	}

	/* sanitize input */
	if (strlen(day) > 0) {
		CharLower(day);
	} else {
		return 0;
	}

	do {
		if (day[0] == 'm') { if (strncmp(day, "monday", 6) == 0) { systemtime->wDayOfWeek = 1; break; } }
		if (day[0] == 't') { if (strncmp(day, "tuesday", 7) == 0) { systemtime->wDayOfWeek = 2; break; } 	
							 if (strncmp(day, "thursday", 8) == 0) { systemtime->wDayOfWeek = 4; break; } }
		if (day[0] == 'w') { if (strncmp(day, "wednesday", 9) == 0) { systemtime->wDayOfWeek = 3; break; } }
		if (day[0] == 'f') { if (strncmp(day, "friday", 6) == 0) { systemtime->wDayOfWeek = 5; break; } }
		if (day[0] == 's') { if (strncmp(day, "saturday", 8) == 0) { systemtime->wDayOfWeek = 6; break; }
							 if (strncmp(day, "sunday", 6) == 0) { systemtime->wDayOfWeek = 0; break; } }
		
		return 0;
	} while (0);


	if (systemtime->wMonth < 1 || systemtime->wMonth > 12) {
		return 0;
	}
	if (systemtime->wDay < 1 || systemtime->wDay > 31) {
		return 0;
	}
	if (systemtime->wYear < 1601 || systemtime->wYear > 30827) {
		return 0;
	}

	if (strlen(daynight) > 0) {
		CharLower(daynight);
	} else {
		return 0;
	}
	if (strncmp(daynight, "am", 2) == 0) {
		if (systemtime->wHour < 1 || systemtime->wHour > 12) {
			return 0;
		}
	} else if (strncmp(daynight, "pm", 2) == 0) {
		if (systemtime->wHour < 1 || systemtime->wHour > 12) {
			return 0;
		}
		if (systemtime->wHour != 12) { systemtime->wHour += 12; }
	} else {
		return 0;
	}

	if(systemtime->wMinute < 0 || systemtime->wMinute > 59) {
		return 0;
	}
	if(systemtime->wSecond < 0 || systemtime->wSecond > 59) {
		return 0;
	}

	/* it doesnt matter what the millisecond value is because the ntfs resolution for file timestamps is only up to 1s */
	systemtime->wMilliseconds = 0;

	return 1;
}

// takes a file a sets the time values to the minimum possible value, return 1 on success or 0 on failure
DWORD SetMinimumTimeValues(char *filename) {

	HANDLE file = NULL;
	FILE_BASIC_INFORMATION fbi;
	SYSTEMTIME userinputtime;

	// open the file and retrieve information
	file = RetrieveFileBasicInformation(filename, &fbi);
	if (file == NULL) {
		return 0;
	}

	userinputtime.wYear = 1601;
	userinputtime.wMonth = 1;
	userinputtime.wDayOfWeek = 0;
	userinputtime.wDay = 1;
	userinputtime.wHour = 0;
	userinputtime.wMinute = 0;
	userinputtime.wSecond = 0;
	userinputtime.wMilliseconds = 0;
	if ((ConvertLocalTimeToLargeInteger(userinputtime, &fbi.ChangeTime) == 0) || (ConvertLocalTimeToLargeInteger(userinputtime, &fbi.CreationTime) == 0) ||
		(ConvertLocalTimeToLargeInteger(userinputtime, &fbi.LastAccessTime) == 0) || (ConvertLocalTimeToLargeInteger(userinputtime, &fbi.LastWriteTime) == 0)) {
		return 0;
	}	
	if (SetFileMACE(file, fbi) == 0) { return 0; }

	return 1;
}

// this function recursively blanks all files from the specified directory so that EnCase cannot see anything
DWORD TheCraigOption(char *directoryname) {
	
	// general variables
	HANDLE file = NULL;
	char currentfiletarget[MAX_PATH + 1];

	// file search variables
	HANDLE find = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA FindFileData;
	char fulldirectorypath[MAX_PATH + 1];

	// set the target directories
	strncpy(fulldirectorypath, directoryname, strlen(directoryname)+1);
	strncat(fulldirectorypath, "\\*", 3);
	
	// search the directory
	find = FindFirstFile(fulldirectorypath, &FindFileData);
	if (find == INVALID_HANDLE_VALUE) {
		if (GetLastError() == 5) { // access denied
			return 1;
		}
		return 0;
	}

	// recursively call TheCraigOption if the file type is a directory
	if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		if ((strncmp(FindFileData.cFileName, ".", 1) != 0) && (strncmp(FindFileData.cFileName, "..", 2) != 0)) {
			strncpy(currentfiletarget, directoryname, strlen(directoryname) + 1);
			strncat(currentfiletarget, "\\", 2);
			strncat(currentfiletarget, FindFileData.cFileName, strlen(FindFileData.cFileName));
			if (TheCraigOption(currentfiletarget) == 0) {
				return 0;
			}
		}
	} else {
		// set the full file name and lower the time values
		strncpy(currentfiletarget, directoryname, strlen(directoryname) + 1);
		strncat(currentfiletarget, "\\", 2);
		strncat(currentfiletarget, FindFileData.cFileName, strlen(FindFileData.cFileName));
		if (SetMinimumTimeValues(currentfiletarget) == 0) {
			//return 0;
		}
	}

	// recursively set all values
	while (FindNextFile(find, &FindFileData) != 0) {

		// recursively call TheCraigOption if the file type is a directory
		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if ((strncmp(FindFileData.cFileName, ".", 1) != 0) && (strncmp(FindFileData.cFileName, "..", 2) != 0)) {
				strncpy(currentfiletarget, directoryname, strlen(directoryname) + 1);
				strncat(currentfiletarget, "\\", 2);
				strncat(currentfiletarget, FindFileData.cFileName, strlen(FindFileData.cFileName));
				if (TheCraigOption(currentfiletarget) == 0) {
					return 0;
				}
			}
		} else {
			// set the full file name and lower the time values
			strncpy(currentfiletarget, directoryname, strlen(directoryname) + 1);
			strncat(currentfiletarget, "\\", 2);
			strncat(currentfiletarget, FindFileData.cFileName, strlen(FindFileData.cFileName));
			if (SetMinimumTimeValues(currentfiletarget) == 0) {
				//return 0;
			}
		}
	}

	// cleanup find data structures
	if (FindClose(find) == 0) {
		return 0;
	}
	if (GetLastError() != ERROR_NO_MORE_FILES) {
		if (GetLastError() == 5) { // access denied
			return 1;
		}
		return 0;
	}

	return 1;
}
