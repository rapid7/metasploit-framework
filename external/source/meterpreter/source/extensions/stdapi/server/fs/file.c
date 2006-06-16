#include "precomp.h"
#include <sys/stat.h>

/***************************
 * File Channel Operations *
 ***************************/

typedef struct
{
	FILE  *fd;
	DWORD mode;
} FileContext;

/*
 * Writes the supplied data to the file
 */
static DWORD file_channel_write(Channel *channel, Packet *request, 
		LPVOID context, LPVOID buffer, DWORD bufferSize,
		LPDWORD bytesWritten)
{
	FileContext *ctx = (FileContext *)context;
	DWORD result= ERROR_SUCCESS;
	LONG written = 0;

	// Write a chunk
	if ((written = fwrite(buffer, 1, bufferSize, ctx->fd)) <= 0)
	{
		written = 0;
		result  = GetLastError();
	}

	// Set bytesWritten
	if (bytesWritten)
		*bytesWritten = written;

	return result;
}

/*
 * Closes the file
 */
static DWORD file_channel_close(Channel *channel, Packet *request, 
		LPVOID context)
{
	FileContext *ctx = (FileContext *)context;
			
	fclose(ctx->fd);
	free(ctx);

	return ERROR_SUCCESS;
}

/*
 * Reads data from the file (if any)
 */
static DWORD file_channel_read(Channel *channel, Packet *request, 
		LPVOID context, LPVOID buffer, DWORD bufferSize,
		LPDWORD bytesRead)
{
	FileContext *ctx = (FileContext *)context;
	DWORD result = ERROR_SUCCESS;
	LONG bytes = 0;

	// Read a chunk
	if ((bytes= fread(buffer, 1, bufferSize, ctx->fd)) <= 0)
	{
		bytes = 0;
		result = GetLastError();
	}

	// Set bytesRead
	if (bytesRead)
		*bytesRead = bytes;

	return ERROR_SUCCESS;
}

/*
 * Checks to see if the file pointer is currently at the end of the file
 */
static DWORD file_channel_eof(Channel *channel, Packet *request, 
		LPVOID context, LPBOOL isEof)
{
	FileContext *ctx = (FileContext *)context;
	
	return feof(ctx->fd) ? TRUE : FALSE;
}

/*
 * Changes the current file pointer position in the file
 */
static DWORD file_channel_seek(Channel *channel, Packet *request, 
		LPVOID context, LONG offset, DWORD whence)
{
	FileContext *ctx = (FileContext *)context;
		
	return fseek(ctx->fd, offset, whence);
}

/*
 * Returns the current offset in the file to the requestor
 */
static DWORD file_channel_tell(Channel *channel, Packet *request, 
		LPVOID context, LPLONG offset)
{
	FileContext *ctx = (FileContext *)context;
	DWORD result = ERROR_SUCCESS;
	LONG pos = 0;
		
	if ((pos = ftell(ctx->fd)) < 0)
		result = GetLastError();

	if (offset)
		*offset = pos;

	return result;
}

/*
 * Handles the open request for a file channel and returns a valid channel
 * identifier to the requestor if the file is opened successfully
 */
DWORD request_fs_file_channel_open(Remote *remote, Packet *packet)
{
	Packet *response = NULL;
	PCHAR filePath, mode;
	DWORD res = ERROR_SUCCESS;
	DWORD flags = 0;
	Channel *newChannel = NULL;
	PoolChannelOps chops = { 0 };
	FileContext *ctx;
	LPSTR expandedFilePath = NULL;

	do
	{
		// Allocate a response
		response = packet_create_response(packet);

		// Get the channel flags
		flags = packet_get_tlv_value_uint(packet, TLV_TYPE_FLAGS);

		// Allocate storage for the file context
		if (!(ctx = (FileContext *)malloc(sizeof(FileContext))))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the file path and the mode
		filePath = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);
		mode     = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_MODE);

		// No file path? bogus.
		if (!filePath)
		{
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		// Expand the file path
		if (!(expandedFilePath = fs_expand_path(filePath)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
	
		if (!mode)
			mode = "rb";

		// Invalid file?
		if (!(ctx->fd = fopen(expandedFilePath, mode)))
		{
			res = GetLastError();
			break;
		}

		memset(&chops, 0, sizeof(chops));

		// Initialize the pool operation handlers
		chops.native.context = ctx;
		chops.native.write   = file_channel_write;
		chops.native.close   = file_channel_close;
		chops.read           = file_channel_read;
		chops.eof            = file_channel_eof;
		chops.seek           = file_channel_seek;
		chops.tell           = file_channel_tell;

		// Check the response allocation & allocate a un-connected
		// channel
		if ((!response) ||
		    (!(newChannel = channel_create_pool(0, flags,
				&chops))))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the channel identifier to the response
		packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, 
				channel_get_id(newChannel));

	} while (0);

	// Transmit the packet if it's valid
	packet_transmit_response(res, remote, response);

	// Clean up on failure
	if (res != ERROR_SUCCESS)
	{
		if (newChannel)
			channel_destroy(newChannel, NULL);
		if (ctx)
			free(ctx);
	}

	// Free the expanded file path if it was allocated
	if (expandedFilePath)
		free(expandedFilePath);

	return res;
}

/*
 * Gets information about the file path that is supplied and returns it to the
 * requestor
 *
 * TLVs:
 *
 * req: TLV_TYPE_FILE_PATH - The file path that is to be stat'd
 */
DWORD request_fs_stat(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	struct stat buf;
	LPCSTR filePath;
	LPSTR expanded = NULL;
	DWORD result = ERROR_SUCCESS;

	filePath = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);

	// Validate parameters
	if (!filePath)
		result = ERROR_INVALID_PARAMETER;
	else if (!(expanded = fs_expand_path(filePath)))
		result = ERROR_NOT_ENOUGH_MEMORY;
	else
	{
		// Stat the file using the Microsoft stat wrapper so that we don't have to
		// do translations
		if (stat(expanded, &buf) < 0)
			result = GetLastError();
		else
			packet_add_tlv_raw(response, TLV_TYPE_STAT_BUF, &buf,
					sizeof(buf));
	}

	// Set the result and transmit the response
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, result);

	packet_transmit(remote, response, NULL);

	if (expanded)
		free(expanded);

	return ERROR_SUCCESS;
}

/*
 * Expands a file path and returns the expanded path to the requestor
 *
 * req: TLV_TYPE_FILE_PATH - The file path to expand
 */
DWORD request_fs_file_expand_path(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	LPSTR expanded = NULL;
	LPSTR regular;

	regular = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);

	do
	{
		// No regular path?
		if (!regular)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Allocate storage for the expanded path
		if (!(expanded = fs_expand_path(regular)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		packet_add_tlv_string(response, TLV_TYPE_FILE_PATH, expanded);

	} while (0);

	// Transmit the response to the mofo
	packet_transmit_response(result, remote, response);

	if (expanded)
		free(expanded);

	return ERROR_SUCCESS;
}
