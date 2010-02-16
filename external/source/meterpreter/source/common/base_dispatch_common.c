#include "common.h"

/*
 * core_channel_open
 * -----------------
 *
 * Opens a channel with the remote endpoint.  The response handler for this
 * request will establish the relationship on the other side.
 *
 * opt: TLV_TYPE_CHANNEL_TYPE 
 *      The channel type to allocate.  If set, the function returns, allowing
 *      a further up extension handler to allocate the channel.
 */
DWORD remote_request_core_channel_open(Remote *remote, Packet *packet)
{
	Packet *response;
	DWORD res = ERROR_SUCCESS;
	Channel *newChannel;
	PCHAR channelType;
	DWORD flags = 0;

	do
	{
		// If the channel open request had a specific channel type
		if ((channelType = packet_get_tlv_value_string(packet, 
				TLV_TYPE_CHANNEL_TYPE)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Get any flags that were supplied
		flags = packet_get_tlv_value_uint(packet, TLV_TYPE_FLAGS);

		// Allocate a response
		response = packet_create_response(packet);
		
		// Did the response allocation fail?
		if ((!response) ||
		    (!(newChannel = channel_create(0, flags))))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the channel class and set it
		newChannel->cls = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_CLASS);

		// Add the new channel identifier to the response
		if ((res = packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID,
				channel_get_id(newChannel))) != ERROR_SUCCESS)
			break;

		// Transmit the response
		res = packet_transmit(remote, response, NULL);

	} while (0);

	return res;
}

/*
 * core_channel_open (response)
 * -----------------
 *
 * Handles the response to a request to open a channel.
 *
 * This function takes the supplied channel identifier and creates a
 * channel list entry with it.
 *
 * req: TLV_TYPE_CHANNEL_ID -- The allocated channel identifier
 */
DWORD remote_response_core_channel_open(Remote *remote, Packet *packet)
{
	DWORD res = ERROR_SUCCESS, channelId;
	Channel *newChannel;

	do
	{
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);
		
		// DId the request fail?
		if (!channelId)
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Create a local instance of the channel with the supplied identifier
		if (!(newChannel = channel_create(channelId, 0)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

	} while (0);

	return res;
}

/*
 * core_channel_write
 * ------------------
 *
 * Write data from a channel into the local output buffer for it
 */
DWORD remote_request_core_channel_write(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS, channelId, written = 0;
	Tlv channelData;
	Channel * channel = NULL;

	do
	{
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

		// Try to locate the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		lock_acquire( channel->lock );

		// Get the channel data buffer
		if ((res = packet_get_tlv(packet, TLV_TYPE_CHANNEL_DATA, &channelData)) != ERROR_SUCCESS)
			break;

		// Handle the write operation differently based on the class of channel
		switch (channel_get_class(channel))
		{
			// If it's buffered, write it to the local buffer cache
			case CHANNEL_CLASS_BUFFERED:
				res = channel_write_to_buffered(channel, channelData.buffer, channelData.header.length, (PULONG)&written);
				break;
			// If it's non-buffered, call the native write operation handler if
			// one is implemented
			default:
				{
					NativeChannelOps *ops = (NativeChannelOps *)&channel->ops;
					if (ops->write)
						res = ops->write(channel, packet, ops->context, 
								channelData.buffer, channelData.header.length, 
								&written);
					else
						res = ERROR_NOT_SUPPORTED;
				}
				break;
		}

	} while (0);

	if( channel )
		lock_release( channel->lock );

	// Transmit the acknowledgement
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);
		packet_add_tlv_uint(response, TLV_TYPE_LENGTH, written);
		packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channelId);

		res = packet_transmit(remote, response, NULL);
	}

	return res;
}

/*
 * core_channel_read
 * -----------------
 *
 * From from the local buffer and write back to the requester
 *
 * Takes TLVs:
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to read from
 * req: TLV_TYPE_LENGTH     -- The number of bytes to read
 */
DWORD remote_request_core_channel_read(Remote *remote, Packet *packet)
{
	DWORD res = ERROR_SUCCESS, bytesToRead, bytesRead, channelId;
	Packet *response = packet_create_response(packet);
	PUCHAR temporaryBuffer = NULL;
	Channel *channel = NULL;

	do
	{
		if (!response)
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the number of bytes to read
		bytesToRead = packet_get_tlv_value_uint(packet, TLV_TYPE_LENGTH);
		channelId   = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

		// Try to locate the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		lock_acquire( channel->lock );

		// Allocate temporary storage
		if (!(temporaryBuffer = (PUCHAR)malloc(bytesToRead)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		switch (channel_get_class(channel))
		{
			// If it's buffered, read from the local buffer and either transmit 
			// the buffer in the response or write it back asynchronously
			// depending on the mode of the channel.
			case CHANNEL_CLASS_BUFFERED:
				// Read in from local
				res = channel_read_from_buffered(channel, temporaryBuffer, 
				    bytesToRead, (PULONG)&bytesRead);
				break;
			// Handle read I/O for the pool class
			case CHANNEL_CLASS_POOL:
				// If the channel has a read handler
				if (channel->ops.pool.read)
					res = channel->ops.pool.read(channel, packet, 
							channel->ops.pool.native.context, temporaryBuffer, 
							bytesToRead, &bytesRead);
				else
					res = ERROR_NOT_SUPPORTED;
				break;
			default:
				res = ERROR_NOT_SUPPORTED;
		}

		// If we've so far been successful and we have a temporary buffer...
		if ((res == ERROR_SUCCESS) &&(temporaryBuffer) && (bytesRead))
		{
			// If the channel should operate synchronously, add the data to theresponse
			if (channel_is_flag(channel, CHANNEL_FLAG_SYNCHRONOUS))
			{
				// if the channel data is ment to be compressed, compress it!
				if( channel_is_flag( channel, CHANNEL_FLAG_COMPRESS ) )
					packet_add_tlv_raw(response, TLV_TYPE_CHANNEL_DATA|TLV_META_TYPE_COMPRESSED, temporaryBuffer, bytesRead);
				else
					packet_add_tlv_raw(response, TLV_TYPE_CHANNEL_DATA, temporaryBuffer, bytesRead);

				res = ERROR_SUCCESS;
			}
			// Otherwise, asynchronously write the buffer to the remote endpoint
			else
			{
				if ((res = channel_write(channel, remote, NULL, 0, temporaryBuffer, bytesRead, NULL)) != ERROR_SUCCESS)
					break;
			}
		}

	} while (0);
	
	if( channel )
		lock_release( channel->lock );

	if (temporaryBuffer)
		free(temporaryBuffer);

	// Transmit the acknowledgement
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);
		packet_add_tlv_uint(response, TLV_TYPE_LENGTH, bytesRead);
		packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channelId);

		res = packet_transmit(remote, response, NULL);
	}

	return res;
}

/*
 * core_channel_close
 * ------------------
 *
 * Closes a previously opened channel.
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to close
 */
DWORD remote_request_core_channel_close(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS, channelId;
	Channel *channel = NULL;
		
	dprintf( "[CHANNEL] remote_request_core_channel_close." );

	do
	{
		// Get the channel identifier
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

		// Try to locate the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Destroy the channel
		channel_destroy(channel, packet);

		if (response)
			packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channelId);

	} while (0);

	// Transmit the acknowledgement
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

		res = packet_transmit(remote, response, NULL);
	}

	return res;
}

/*
 * core_channel_close (response)
 * ------------------
 *
 * Removes the local instance of the channel
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to close
 */
DWORD remote_response_core_channel_close(Remote *remote, Packet *packet)
{
	DWORD res = ERROR_SUCCESS, channelId;
	Channel *channel = NULL;

	do
	{
		// Get the channel identifier
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

		// Try to locate the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Destroy the channel
		channel_destroy(channel, packet);

	} while (0);

	return res;
}


/*
 * core_channel_seek
 * -----------------
 *
 * req: TLV_TYPE_CHANNEL_ID  -- The channel identifier to seek on
 * req: TLV_TYPE_SEEK_OFFSET -- The offset to seek to
 * req: TLV_TYPE_SEEK_WHENCE -- The relativity to which the offset refers
 */
DWORD remote_request_core_channel_seek(Remote *remote, Packet *packet)
{
	Channel *channel = NULL;
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;

	do
	{
		// Lookup the channel by its identifier
		if (!(channel = channel_find_by_id(
				packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID))))
		{
			result = ERROR_NOT_FOUND;
			break;
		}

		lock_acquire( channel->lock );

		// Make sure this class is compatible
		if (channel_get_class(channel) != CHANNEL_CLASS_POOL)
		{
			result = ERROR_NOT_SUPPORTED;
			break;
		}

		// Call the function if it's set
		if (channel->ops.pool.seek)
			result = channel->ops.pool.seek(channel, packet, 
					channel->ops.pool.native.context, 
					(LONG)packet_get_tlv_value_uint(packet, TLV_TYPE_SEEK_OFFSET),
					packet_get_tlv_value_uint(packet, TLV_TYPE_SEEK_WHENCE));
		else
			result = ERROR_NOT_SUPPORTED;

	} while (0);
	
	if( channel )
		lock_release( channel->lock );

	// Transmit the result
	packet_transmit_response(result, remote, response);

	return result;
}

/*
 * core_channel_eof
 * -----------------
 *
 * req: TLV_TYPE_CHANNEL_ID  -- The channel identifier to check eof on
 */
DWORD remote_request_core_channel_eof(Remote *remote, Packet *packet)
{
	Channel *channel = NULL;
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	BOOL isEof = FALSE;

	do
	{
		// Lookup the channel by its identifier
		if (!(channel = channel_find_by_id(
				packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID))))
		{
			result = ERROR_NOT_FOUND;
			break;
		}

		lock_acquire( channel->lock );

		// Make sure this class is compatible
		if (channel_get_class(channel) != CHANNEL_CLASS_POOL)
		{
			result = ERROR_NOT_SUPPORTED;
			break;
		}

		// Call the function if it's set
		if (channel->ops.pool.eof)
			result = channel->ops.pool.eof(channel, packet, 
					channel->ops.pool.native.context, 
					&isEof);
		else
			result = ERROR_NOT_SUPPORTED;

	} while (0);
	
	if( channel )
		lock_release( channel->lock );

	// Add the EOF flag
	packet_add_tlv_bool(response, TLV_TYPE_BOOL, isEof);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return result;
}

/*
 * core_channel_tell
 * -----------------
 *
 * req: TLV_TYPE_CHANNEL_ID  -- The channel identifier to check tell on
 */
DWORD remote_request_core_channel_tell(Remote *remote, Packet *packet)
{
	Channel *channel = NULL;
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	LONG offset = 0;

	do
	{
		// Lookup the channel by its identifier
		if (!(channel = channel_find_by_id(
				packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID))))
		{
			result = ERROR_NOT_FOUND;
			break;
		}

		lock_acquire( channel->lock );

		// Make sure this class is compatible
		if (channel_get_class(channel) != CHANNEL_CLASS_POOL)
		{
			result = ERROR_NOT_SUPPORTED;
			break;
		}

		// Call the function if it's set
		if (channel->ops.pool.tell)
			result = channel->ops.pool.tell(channel, packet, 
					channel->ops.pool.native.context, 
					&offset);
		else
			result = ERROR_NOT_SUPPORTED;

	} while (0);

	if( channel )
		lock_release( channel->lock );

	// Add the offset
	packet_add_tlv_uint(response, TLV_TYPE_SEEK_POS, offset);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return result;
}


/*
 * core_channel_interact
 * ---------------------
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to interact with
 * req: TLV_TYPE_BOOL       -- True if interactive, false if not.
 */
DWORD remote_request_core_channel_interact(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	Channel *channel = NULL;
	DWORD channelId;
	DWORD result = ERROR_SUCCESS;
	BOOLEAN interact;

	// Get the channel identifier
	channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);
	interact  = packet_get_tlv_value_bool(packet, TLV_TYPE_BOOL);

	// If the channel is found, set the interactive flag accordingly
	if ((channel = channel_find_by_id(channelId)))
	{
		lock_acquire( channel->lock );

		// If the response packet is valid
		if ((response) &&
		    (channel_get_class(channel) != CHANNEL_CLASS_BUFFERED))
		{
			NativeChannelOps *native = (NativeChannelOps *)&channel->ops;

			// Check to see if this channel has a registered interact handler
			if (native->interact)
				result = native->interact(channel, packet, native->context, 
						interact);
		}

		// Set the channel's interactive state
		channel_set_interactive(channel, interact);

		lock_release( channel->lock );
	}

	// Send the response to the requestor so that the interaction can be 
	// complete
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * core_crypto_negotiate
 * ---------------------
 *
 * Negotiates a cryptographic session with the remote host
 *
 * req: TLV_TYPE_CIPHER_NAME       -- The cipher being selected.
 * opt: TLV_TYPE_CIPHER_PARAMETERS -- The paramters passed to the cipher for
 *                                    initialization
 */
DWORD remote_request_core_crypto_negotiate(Remote *remote, Packet *packet)
{
	LPCSTR cipherName = packet_get_tlv_value_string(packet,
			TLV_TYPE_CIPHER_NAME);
	DWORD res = ERROR_INVALID_PARAMETER;
	Packet *response = packet_create_response(packet);

	// If a cipher name was supplied, set it
	if (cipherName)
		res = remote_set_cipher(remote, cipherName, packet);

	// Transmit a response
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

		packet_transmit(remote, response, NULL);
	}

	return ERROR_SUCCESS;
}
