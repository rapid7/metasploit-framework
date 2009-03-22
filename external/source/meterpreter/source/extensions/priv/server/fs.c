#include "precomp.h"

// Import code from timestomp
#include "timestomp.c"

#define EpochTimeToSystemTime(epoch, sys) \
	{ \
		struct tm *et = localtime(&epoch); \
		memset(sys, 0, sizeof(SYSTEMTIME)); \
		(sys)->wYear    = et->tm_year + 1900; \
		(sys)->wMonth   = et->tm_mon + 1; \
		(sys)->wDay     = et->tm_mday; \
		(sys)->wHour    = et->tm_hour; \
		(sys)->wMinute  = et->tm_min; \
		(sys)->wSecond  = et->tm_sec; \
	}

#define SystemTimeToEpochTime(sys, epoch) \
	{ \
		struct tm et; \
		memset(&et, 0, sizeof(et)); \
		et.tm_year = (sys)->wYear - 1900; \
		et.tm_mon  = (sys)->wMonth -1; \
		et.tm_mday = (sys)->wDay; \
		et.tm_hour = (sys)->wHour; \
		et.tm_min  = (sys)->wMinute; \
		et.tm_sec  = (sys)->wSecond; \
		*(epoch) = mktime(&et); \
	}


DWORD request_fs_get_file_mace(Remote *remote, Packet *packet)
{
	FILE_BASIC_INFORMATION fbi;
	SYSTEMTIME lt;
	Packet *response = packet_create_response(packet);
	HANDLE file = NULL;
	PCHAR filePath = packet_get_tlv_value_string(packet, TLV_TYPE_FS_FILE_PATH);
	struct {
		LARGE_INTEGER *ft;
		unsigned long tlv;
	} fields[] = {
		{ &fbi.LastWriteTime,  TLV_TYPE_FS_FILE_MODIFIED  },
		{ &fbi.LastAccessTime, TLV_TYPE_FS_FILE_ACCESSED  },
		{ &fbi.CreationTime,   TLV_TYPE_FS_FILE_CREATED   },
		{ &fbi.ChangeTime,     TLV_TYPE_FS_FILE_EMODIFIED },
	};
	int x;

	do
	{
		// Invalid file path, bail.
		if (!filePath)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			break;
		}

		// If we fail to retrieve basic information, bail.
		if (!(file = RetrieveFileBasicInformation(filePath, &fbi)))
			break;

		// Convert the time for each field
		for (x = 0; x < (sizeof(fields) / sizeof(fields[0])); x++)
		{
			time_t epoch = 0;

			if (ConvertLargeIntegerToLocalTime(&lt, *fields[x].ft) != 1)
				break;

			SystemTimeToEpochTime(&lt, &epoch);

			packet_add_tlv_uint(response, fields[x].tlv, epoch);
		}
		
		SetLastError(ERROR_SUCCESS);

	} while (0);

	// Close the file handle.
	if (file)
		CloseHandle(file);

	packet_transmit_response(GetLastError(), remote, response);

	return ERROR_SUCCESS;
}

DWORD request_fs_set_file_mace(Remote *remote, Packet *packet)
{
	FILE_BASIC_INFORMATION fbi;
	Packet *response = packet_create_response(packet);
	HANDLE file = NULL;
	PCHAR filePath = packet_get_tlv_value_string(packet, TLV_TYPE_FS_FILE_PATH);
	struct {
		LARGE_INTEGER *ft;
		unsigned long tlv;
	} fields[] = {
		{ &fbi.LastWriteTime,  TLV_TYPE_FS_FILE_MODIFIED  },
		{ &fbi.LastAccessTime, TLV_TYPE_FS_FILE_ACCESSED  },
		{ &fbi.CreationTime,   TLV_TYPE_FS_FILE_CREATED   },
		{ &fbi.ChangeTime,     TLV_TYPE_FS_FILE_EMODIFIED },
	};
	int x;

	do
	{
		// Invalid file path, bail.
		if (!filePath)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			break;
		}

		// If we fail to retrieve basic information, bail.
		if (!(file = RetrieveFileBasicInformation(filePath, &fbi)))
			break;

		// If the TLV for the associated field is supplied, update it.
		for (x = 0; x < (sizeof(fields) / sizeof(fields[0])); x++)
		{
			SYSTEMTIME st;
			unsigned long epoch = packet_get_tlv_value_uint(packet, fields[x].tlv);

			if (!epoch)
				continue;

			EpochTimeToSystemTime(epoch, &st);

			// Conversion failed, that sucks.
			if (ConvertLocalTimeToLargeInteger(st, fields[x].ft) == 0)
				break;
		}

		// If we fail to set the MACE, bail.
		if (SetFileMACE(file, fbi) == 0)
			break;

		SetLastError(ERROR_SUCCESS);

	} while (0);

	// Close the file handle.
	if (file)
		CloseHandle(file);

	packet_transmit_response(GetLastError(), remote, response);

	return ERROR_SUCCESS;
}

DWORD request_fs_set_file_mace_from_file(Remote *remote, Packet *packet)
{
	FILE_BASIC_INFORMATION fbi;
	Packet *response = packet_create_response(packet);
	PCHAR tgtFilePath = packet_get_tlv_value_string(packet, TLV_TYPE_FS_FILE_PATH);
	PCHAR srcFilePath = packet_get_tlv_value_string(packet, TLV_TYPE_FS_SRC_FILE_PATH);
	HANDLE srcFile = NULL, tgtFile = NULL;
	ULONG attributes;

	do
	{
		// Are we missing something?
		if (!tgtFilePath || !srcFilePath)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			break;
		}

		// Get info.
		if (!(tgtFile = RetrieveFileBasicInformation(tgtFilePath, &fbi)))
			break;
		attributes = fbi.FileAttributes;
		if (!(srcFile = RetrieveFileBasicInformation(srcFilePath, &fbi)))
			break;
		fbi.FileAttributes = attributes;

		if (SetFileMACE(tgtFile, fbi) == 0)
			break;

		SetLastError(ERROR_SUCCESS);

	} while (0);

	if (srcFile)
		CloseHandle(srcFile);
	if (tgtFile)
		CloseHandle(tgtFile);

	packet_transmit_response(GetLastError(), remote, response);

	return ERROR_SUCCESS;
}

DWORD request_fs_blank_file_mace(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	PCHAR filePath = packet_get_tlv_value_string(packet, TLV_TYPE_FS_FILE_PATH);

	do
	{
		// Are we missing something?
		if (!filePath)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			break;
		}

		if (SetMinimumTimeValues(filePath) == 0)
			break;

		SetLastError(ERROR_SUCCESS);

	} while (0);

	packet_transmit_response(GetLastError(), remote, response);

	return ERROR_SUCCESS;
}

DWORD request_fs_blank_directory_mace(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	PCHAR filePath = packet_get_tlv_value_string(packet, TLV_TYPE_FS_FILE_PATH);

	do
	{
		// Are we missing something?
		if (!filePath)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			break;
		}

		if (TheCraigOption(filePath) == 0)
			break;

		SetLastError(ERROR_SUCCESS);

	} while (0);

	packet_transmit_response(GetLastError(), remote, response);

	return ERROR_SUCCESS;
}
