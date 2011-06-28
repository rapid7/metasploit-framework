#include "common.h"

DWORD packet_find_tlv_buf(Packet *packet, PUCHAR payload, DWORD payloadLength, DWORD index,
		TlvType type, Tlv *tlv);

typedef struct _PacketCompletionRoutineEntry
{
	LPCSTR                               requestId;
	PacketRequestCompletion              handler;
	struct _PacketCompletionRoutineEntry *next;
} PacketCompletionRoutineEntry;

PacketCompletionRoutineEntry *packetCompletionRoutineList = NULL;

/************
 * Core API *
 ************/

/*
 * Transmit a single string to the remote connection with instructions to 
 * print it to the screen or whatever medium has been established.
 */
DWORD send_core_console_write(Remote *remote, LPCSTR fmt, ...)
{
	Packet *request = NULL;
	CHAR buf[8192];
	va_list ap;
	DWORD res;

	do
	{
		va_start(ap, fmt);
		_vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
		va_end(ap);

		// Create a message with the 'core_print' method
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST, "core_console_write")))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the string to print
		if ((res = packet_add_tlv_string(request, TLV_TYPE_STRING, buf)) != NO_ERROR)
			break;

		res = packet_transmit(remote, request, NULL);

	} while (0);

	// Cleanup on failure
	if (res != ERROR_SUCCESS)
	{
		if (request)
			packet_destroy(request);
	}

	return res;
}

/*
 * XXX
 */
HANDLE core_update_thread_token(Remote *remote, HANDLE token)
{
	HANDLE temp = NULL;
#ifdef _WIN32

	lock_acquire( remote->lock );
	do {
		temp = remote->hThreadToken;

		// A NULL token resets the state back to the server token
		if(! token)
			token = remote->hServerToken;

		// Assign the thread token
		remote->hThreadToken = token;

		// Close the old token if its not one of the two active tokens
		if(temp && temp != remote->hServerToken && temp != remote->hThreadToken) {
			CloseHandle(temp);
		}

	} while(0);
	
	lock_release( remote->lock );
#else
	/*
	 * XXX add POSIX implementation
	 */
#endif
	return(token);
}

/*
 * Update the session/station/desktop to be used by multi threaded meterpreter for desktop related operations.
 * We dont store the handles as it is more convienient to use string,s especially as we cant use the regular API
 * to break out of sessions.
 * Note: It is up to the caller to free any station/desktop name provided as internally we use strdup.
 */
VOID core_update_desktop( Remote * remote, DWORD dwSessionID, char * cpStationName, char * cpDesktopName )
{
#ifdef _WIN32
	DWORD temp_session  = -1;
	char * temp_station = NULL;
	char * temp_desktop = NULL;

	lock_acquire( remote->lock );

	do
	{
		temp_session = remote->dwCurrentSessionId;
		// A session id of -1 resets the state back to the servers real session id
		if( dwSessionID = -1 )
			dwSessionID = remote->dwOrigSessionId;
		// Assign the new session id
		remote->dwCurrentSessionId = dwSessionID;
	
		temp_station = remote->cpCurrentStationName;
		// A NULL station resets the station back to the origional process window station
		if( !cpStationName )
			cpStationName = remote->cpOrigStationName;
		// Assign the current window station name to use
		remote->cpCurrentStationName = _strdup( cpStationName );
		// free the memory for the old station name  if its not one of the two active names
		if( temp_station && temp_station != remote->cpOrigStationName && temp_station != remote->cpCurrentStationName )
			free( temp_station );
		
		temp_desktop = remote->cpCurrentDesktopName;
		// A NULL station resets the desktop back to the origional process desktop
		if( !cpDesktopName )
			cpDesktopName = remote->cpOrigDesktopName;
		// Assign the current window desktop name to use
		remote->cpCurrentDesktopName = _strdup( cpDesktopName );
		// free the memory for the old desktop name if its not one of the two active names
		if( temp_desktop && temp_desktop != remote->cpOrigDesktopName && temp_desktop != remote->cpCurrentDesktopName )
			free( temp_desktop );

	} while( 0 );
	
	lock_release( remote->lock );
#endif
}
/*******************
 * Packet Routines *
 *******************/

/*
 * Create a packet of a given type (request/response) and method.
 */
Packet *packet_create(PacketTlvType type, LPCSTR method)
{
	Packet *packet = NULL;
	BOOL success = FALSE;

	do
	{
		if (!(packet = (Packet *)malloc(sizeof(Packet))))
			break;

		memset(packet, 0, sizeof(Packet));

		// Initialize the header length and message type
		packet->header.length = htonl(sizeof(TlvHeader));
		packet->header.type   = htonl((DWORD)type);

		// Initialize the payload to be blank
		packet->payload       = NULL;
		packet->payloadLength = 0;

		// Add the method TLV if provided
		if (method)
		{
			if (packet_add_tlv_string(packet, TLV_TYPE_METHOD, method) != ERROR_SUCCESS)
				break;
		}

		success = TRUE;

	} while (0);

	// Clean up the packet on failure
	if ((!success) && (packet))
	{
		packet_destroy(packet);

		packet = NULL;
	}

	return packet;
}

/*
 * Create a response packet from a request, referencing the requestors 
 * message identifier.
 */
Packet *packet_create_response(Packet *request)
{
	Packet *response = NULL;
	Tlv method, requestId;
	BOOL success = FALSE;
	PacketTlvType responseType;

	if (packet_get_type(request) == PACKET_TLV_TYPE_PLAIN_REQUEST)
		responseType = PACKET_TLV_TYPE_PLAIN_RESPONSE;
	else
		responseType = PACKET_TLV_TYPE_RESPONSE;

	do
	{
		// Get the request TLV's method
		if (packet_get_tlv_string(request, TLV_TYPE_METHOD, &method) != ERROR_SUCCESS)
			break;

		// Try to allocate a response packet
		if (!(response = packet_create(responseType, (PCHAR)method.buffer)))
			break;

		// Get the request TLV's request identifier
		if (packet_get_tlv_string(request, TLV_TYPE_REQUEST_ID, &requestId) != ERROR_SUCCESS)
			break;

		// Add the request identifier to the packet
		packet_add_tlv_string(response, TLV_TYPE_REQUEST_ID, (PCHAR)requestId.buffer);

		success = TRUE;

	} while (0);

	// Cleanup on failure
	if (!success)
	{
		if (response)
			packet_destroy(response);

		response = NULL;
	}

	return response;
}

/*
 * Destroy the packet context and the payload buffer
 */
VOID packet_destroy( Packet * packet )
{
	if( packet == NULL )
		return;

	if( packet->payload )
	{
		memset( packet->payload, 0, packet->payloadLength );
		free( packet->payload );
	}

	if( packet->decompressed_buffers )
	{
		while( TRUE )
		{
			DECOMPRESSED_BUFFER * buf = list_pop( packet->decompressed_buffers );
			if( !buf )
				break;

			if( buf->buffer )
			{
				memset( buf->buffer, 0, buf->length );
				free( buf->buffer );
			}
			
			free( buf );
		}

		list_destroy( packet->decompressed_buffers );
	}

	memset( packet, 0, sizeof(Packet) );

	free( packet );
}

/*
 * Add a TLV as a string, including the null terminator.
 */
DWORD packet_add_tlv_string(Packet *packet, TlvType type, LPCSTR str)
{
	return packet_add_tlv_raw(packet, type, (PUCHAR)str, strlen(str) + 1);
}

/*
 * Add a TLV as a string, including the null terminator.
 */
DWORD packet_add_tlv_uint(Packet *packet, TlvType type, UINT val)
{
	val = htonl(val);

	return packet_add_tlv_raw(packet, type, (PUCHAR)&val, sizeof(val));
}

/*
 * Add a TLV as a QWORD.
 */
DWORD packet_add_tlv_qword(Packet *packet, TlvType type, QWORD val )
{
	val = htonq( val );

	return packet_add_tlv_raw( packet, type, (PUCHAR)&val, sizeof(QWORD) );
}


/*
 * Add a TLV as a bool.
 */
DWORD packet_add_tlv_bool(Packet *packet, TlvType type, BOOL val)
{
	return packet_add_tlv_raw(packet, type, (PUCHAR)&val, 1);
}

/*
 * Add a TLV group.  A TLV group is a TLV that contains multiple sub-TLVs
 */
DWORD packet_add_tlv_group(Packet *packet, TlvType type, Tlv *entries, DWORD numEntries)
{
	DWORD totalSize = 0, 
		offset = 0,
		index = 0, 
		res = ERROR_SUCCESS;
	PCHAR buffer = NULL;

	// Calculate the total TLV size.
	for (index = 0; index < numEntries; index++)
		totalSize += entries[index].header.length + sizeof(TlvHeader);

	do
	{
		// Allocate storage for the complete buffer
		if (!(buffer = (PCHAR)malloc(totalSize)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Copy the memory into the new buffer
		for (index = 0; index < numEntries; index++)
		{
			TlvHeader rawHeader;

			// Convert byte order for storage
			rawHeader.length = htonl(entries[index].header.length + sizeof(TlvHeader));
			rawHeader.type   = htonl((DWORD)entries[index].header.type);

			// Copy the TLV header & payload
			memcpy(buffer + offset, &rawHeader, sizeof(TlvHeader));
			memcpy(buffer + offset + sizeof(TlvHeader), entries[index].buffer, entries[index].header.length);

			// Update the offset into the buffer
			offset += entries[index].header.length + sizeof(TlvHeader);
		}

		// Now add the TLV group with its contents populated
		res = packet_add_tlv_raw(packet, type, buffer, totalSize);

	} while (0);

	// Free the temporary buffer
	if (buffer)
		free(buffer);

	return res;
}

/*
 * Add an array of TLVs
 */
DWORD packet_add_tlvs(Packet *packet, Tlv *entries, DWORD numEntries)
{
	DWORD index;

	for (index = 0; index < numEntries; index++)
		packet_add_tlv_raw(packet, entries[index].header.type, entries[index].buffer, entries[index].header.length);

	return ERROR_SUCCESS;
}

/*
 * Add an arbitrary TLV whose data is to be compressed with zlib.
 */
DWORD packet_add_tlv_raw_compressed(Packet *packet, TlvType type, LPVOID buf, DWORD length)
{
	DWORD result            = ERROR_SUCCESS;
	DWORD headerLength      = sizeof( TlvHeader );
	PUCHAR newPayload       = NULL;
	BYTE * compressed_buf   = NULL;
	DWORD realLength        = 0;
	DWORD newPayloadLength  = 0;
	DWORD compressed_length = (DWORD)( 1.01 * ( length + 12 ) + 1 );

	do
	{
		compressed_buf = (BYTE *)malloc( compressed_length );
		if( !compressed_buf )
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		if( compress2( compressed_buf, &compressed_length, buf, length, Z_BEST_COMPRESSION ) != Z_OK )
		{
			result = ERROR_UNSUPPORTED_COMPRESSION;
			break;
		}

		realLength       = compressed_length + headerLength;
		newPayloadLength = packet->payloadLength + realLength;
		
		// Allocate/Reallocate the packet's payload
		if( packet->payload )
			newPayload = (PUCHAR)realloc(packet->payload, newPayloadLength);
		else
			newPayload = (PUCHAR)malloc(newPayloadLength);
	
		if( !newPayload )
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Populate the new TLV
		((LPDWORD)(newPayload + packet->payloadLength))[0] = htonl(realLength);
		((LPDWORD)(newPayload + packet->payloadLength))[1] = htonl((DWORD)type);

		memcpy(newPayload + packet->payloadLength + headerLength, compressed_buf, compressed_length );

		// Update the header length and payload length
		packet->header.length = htonl(ntohl(packet->header.length) + realLength);
		packet->payload       = newPayload;
		packet->payloadLength = newPayloadLength;

		result = ERROR_SUCCESS;

	} while( 0 );

	if( compressed_buf )
		free( compressed_buf );

	return result;
}

/*
 * Add an arbitrary TLV
 */
DWORD packet_add_tlv_raw(Packet *packet, TlvType type, LPVOID buf, DWORD length)
{
	DWORD headerLength     = sizeof(TlvHeader);
	DWORD realLength       = length + headerLength;
	DWORD newPayloadLength = packet->payloadLength + realLength;
	PUCHAR newPayload      = NULL;

	// check if this TLV is to be compressed...
	if( ( type & TLV_META_TYPE_COMPRESSED ) == TLV_META_TYPE_COMPRESSED )
		return packet_add_tlv_raw_compressed( packet, type, buf, length );

	// Allocate/Reallocate the packet's payload
	if (packet->payload)
		newPayload = (PUCHAR)realloc(packet->payload, newPayloadLength);
	else
		newPayload = (PUCHAR)malloc(newPayloadLength);
	
	if (!newPayload)
		return ERROR_NOT_ENOUGH_MEMORY;

	// Populate the new TLV
	((LPDWORD)(newPayload + packet->payloadLength))[0] = htonl(realLength);
	((LPDWORD)(newPayload + packet->payloadLength))[1] = htonl((DWORD)type);

	memcpy(newPayload + packet->payloadLength + headerLength, buf, length);

	// Update the header length and payload length
	packet->header.length = htonl(ntohl(packet->header.length) + realLength);
	packet->payload       = newPayload;
	packet->payloadLength = newPayloadLength;

	return ERROR_SUCCESS;
}

/*
 * Checks to see if a tlv is null terminated
 */
DWORD packet_is_tlv_null_terminated(Packet *packet, Tlv *tlv)
{
	if ((tlv->header.length) && (tlv->buffer[tlv->header.length - 1] != 0))
		return ERROR_NOT_FOUND;

	return ERROR_SUCCESS;
}

/*
 * Get the type of the packet
 */
PacketTlvType packet_get_type(Packet *packet)
{
	return (PacketTlvType)ntohl(packet->header.type);
}

TlvMetaType packet_get_tlv_meta(Packet *packet, Tlv *tlv)
{
	return TLV_META_TYPE_MASK(tlv->header.type);
}

/*
 * Get the TLV of the given type 
 */
DWORD packet_get_tlv(Packet *packet, TlvType type, Tlv *tlv)
{
	return packet_enum_tlv(packet, 0, type, tlv);
}

/*
 * Get a TLV as a string
 */
DWORD packet_get_tlv_string(Packet *packet, TlvType type, Tlv *tlv)
{
	DWORD res;

	if ((res = packet_get_tlv(packet, type, tlv)) == ERROR_SUCCESS)
		res = packet_is_tlv_null_terminated(packet, tlv);

	return res;
}

/*
 * Enumerate a TLV group (a TLV that consists other multiple sub-TLVs) and 
 * finds the first match of a given type, if it exists.
 */
DWORD packet_get_tlv_group_entry(Packet *packet, Tlv *group, TlvType type, Tlv *entry)
{
	return packet_find_tlv_buf( packet, group->buffer, group->header.length, 0, type, entry);
}

/*
 * Enumerate a TLV, optionally of a specified typed.
 */
DWORD packet_enum_tlv(Packet *packet, DWORD index, TlvType type, Tlv *tlv)
{
	return packet_find_tlv_buf( packet, packet->payload, packet->payloadLength, index, type, tlv);
}

/*
 * Get the value of a string TLV
 */
PCHAR packet_get_tlv_value_string(Packet *packet, TlvType type)
{
	Tlv stringTlv;
	PCHAR string = NULL;

	if (packet_get_tlv_string(packet, type, &stringTlv) == ERROR_SUCCESS)
		string = (PCHAR)stringTlv.buffer;

	return string;
}

/*
 * Get the value of a UINT TLV
 */
UINT packet_get_tlv_value_uint(Packet *packet, TlvType type)
{
	Tlv uintTlv;

	if ((packet_get_tlv(packet, type, &uintTlv) != ERROR_SUCCESS) ||(uintTlv.header.length < sizeof(DWORD)))
		return 0;

	return ntohl(*(LPDWORD)uintTlv.buffer);
}

BYTE * packet_get_tlv_value_raw( Packet * packet, TlvType type )
{
	Tlv tlv;

	if( packet_get_tlv( packet, type, &tlv ) != ERROR_SUCCESS )
		return NULL;

	return tlv.buffer;
}

/*
 * Get the value of a QWORD TLV
 */
QWORD packet_get_tlv_value_qword(Packet *packet, TlvType type)
{
	Tlv qwordTlv;

	if( ( packet_get_tlv( packet, type, &qwordTlv ) != ERROR_SUCCESS ) || ( qwordTlv.header.length < sizeof(QWORD) ) )
		return 0;

	return ntohq( *(QWORD *)qwordTlv.buffer );
}

/*
 * Get the value of a bool TLV
 */
BOOL packet_get_tlv_value_bool(Packet *packet, TlvType type)
{
	Tlv boolTlv;
	BOOL val = FALSE;

	if (packet_get_tlv(packet, type, &boolTlv) == ERROR_SUCCESS)
		val = (BOOL)(*(PCHAR)boolTlv.buffer);

	return val;
}

/*
 * Add an exception to a packet
 */
DWORD packet_add_exception(Packet *packet, DWORD code,
		PCHAR fmt, ...)
{
	DWORD codeNbo = htonl(code);
	char buf[8192];
	Tlv entries[2];
	va_list ap;

	// Ensure null termination
	buf[sizeof(buf) - 1] = 0;

	va_start(ap, fmt);
	_vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);

	// Populate the TLV group array
	entries[0].header.type   = TLV_TYPE_EXCEPTION_CODE;
	entries[0].header.length = 4;
	entries[0].buffer        = (PUCHAR)&codeNbo;
	entries[1].header.type   = TLV_TYPE_EXCEPTION_STRING;
	entries[1].header.length = strlen(buf) + 1;
	entries[1].buffer        = buf;

	// Add the TLV group, or try to at least.
	return packet_add_tlv_group(packet, TLV_TYPE_EXCEPTION, entries, 2);
}

/*
 * Get the result code from the packet
 */
DWORD packet_get_result(Packet *packet)
{
	return packet_get_tlv_value_uint(packet, TLV_TYPE_RESULT);
}

/*
 * Enumerate TLV entries in a buffer until hitting a given index (optionally for a given type as well).
 */
DWORD packet_find_tlv_buf( Packet *packet, PUCHAR payload, DWORD payloadLength, DWORD index, TlvType type, Tlv *tlv)
{
	DWORD currentIndex = 0;
	DWORD offset = 0, length = 0;
	BOOL found = FALSE;
	PUCHAR current;

	memset(tlv, 0, sizeof(Tlv));

	do
	{
		// Enumerate the TLV's
		for( current = payload, length = 0 ; !found && current ; offset += length, current += length )
		{
			TlvHeader *header    = (TlvHeader *)current;
			TlvType current_type = 0;

			if ((current + sizeof(TlvHeader) > payload + payloadLength) || (current < payload))
				break;

			// TLV's length
			length = ntohl(header->length);

			// Matching type?
			current_type = ntohl( header->type );

			// if the type has been compressed, temporarily remove the compression flag as compression is to be transparent.
			if( ( current_type & TLV_META_TYPE_COMPRESSED ) == TLV_META_TYPE_COMPRESSED )
				current_type = current_type ^ TLV_META_TYPE_COMPRESSED;
			
			// check if the types match?
			if( (current_type != type) && (type != TLV_TYPE_ANY) )
				continue;
		
			// Matching index?
			if (currentIndex != index)
			{
				currentIndex++;
				continue;
			}

			if ((current + length > payload + payloadLength) || (current < payload))
				break;

			tlv->header.type   = ntohl(header->type);
			tlv->header.length = ntohl(header->length) - sizeof(TlvHeader);
			tlv->buffer        = payload + offset + sizeof(TlvHeader);

			if( ( tlv->header.type & TLV_META_TYPE_COMPRESSED ) == TLV_META_TYPE_COMPRESSED )
			{
				DECOMPRESSED_BUFFER * decompressed_buf = NULL;

				do
				{
					decompressed_buf = (DECOMPRESSED_BUFFER *)malloc( sizeof(DECOMPRESSED_BUFFER) );
					if( !decompressed_buf )
						break;
					
					// the first DWORD in a compressed buffer is the decompressed buffer length.
					decompressed_buf->length = ntohl( *(DWORD *)tlv->buffer );
					if( !decompressed_buf->length )
						break;

					decompressed_buf->buffer = (BYTE *)malloc( decompressed_buf->length );
					if( !decompressed_buf->buffer )
						break;

					tlv->header.length -= sizeof( DWORD );
					tlv->buffer += sizeof( DWORD );
					
					if( uncompress( decompressed_buf->buffer, &decompressed_buf->length, tlv->buffer, tlv->header.length ) != Z_OK )
						break;
					
					tlv->header.type   = tlv->header.type ^ TLV_META_TYPE_COMPRESSED;
					tlv->header.length = decompressed_buf->length;
					tlv->buffer        = decompressed_buf->buffer;

					if( !packet->decompressed_buffers )
						packet->decompressed_buffers = list_create();
					
					if( !packet->decompressed_buffers )
						break;

					// each packet has a list of decompressed buffers which is used to
					// wipe and fee all decompressed buffers upon the packet being destroyed.
					list_push( packet->decompressed_buffers, decompressed_buf );

					found = TRUE;

				} while( 0 );

				if( !found && decompressed_buf )
				{
					if( decompressed_buf->buffer )
						free( decompressed_buf->buffer );
					free( decompressed_buf );
				}
			}
			else
			{
				found = TRUE;
			}
		}

	} while (0);

	return (found) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
}

/***********************
 * Completion Routines *
 ***********************/

/*
 * Add a completion routine for a given request identifier
 */
DWORD packet_add_completion_handler(LPCSTR requestId, PacketRequestCompletion *completion)
{
	PacketCompletionRoutineEntry *entry;
	DWORD res = ERROR_SUCCESS;

	do
	{
		// Allocate the entry
		if (!(entry = (PacketCompletionRoutineEntry *)malloc(sizeof(PacketCompletionRoutineEntry))))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Copy the completion routine information
		memcpy(&entry->handler, completion, sizeof(PacketRequestCompletion));

		// Copy the request identifier
		if (!(entry->requestId = _strdup(requestId)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;

			free(entry);

			break;
		}

		// Add the entry to the list
		entry->next                 = packetCompletionRoutineList;
		packetCompletionRoutineList = entry;

	} while (0);

	return res;
}

/*
 * Call the register completion handler(s) for the given request identifier.
 */
DWORD packet_call_completion_handlers(Remote *remote, Packet *response,LPCSTR requestId)
{
	PacketCompletionRoutineEntry *current;
	DWORD result = packet_get_result(response);
	DWORD matches = 0;
	Tlv methodTlv;
	LPCSTR method = NULL;

	// Get the method associated with this packet
	if (packet_get_tlv_string(response, TLV_TYPE_METHOD,
			&methodTlv) == ERROR_SUCCESS)
		method = (LPCSTR)methodTlv.buffer;

	// Enumerate the completion routine list
	for (current = packetCompletionRoutineList;
	     current;
	     current = current->next)
	{
		// Does the request id of the completion entry match the packet's request 
		// id?
		if (strcmp(requestId, current->requestId))
			continue;

		// Call the completion routine
		current->handler.routine(remote, response, current->handler.context,
				method, result);

		// Increment the number of matched handlers
		matches++;
	}

	if (matches)
		packet_remove_completion_handler(requestId);

	return (matches > 0) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
}

/*
 * Remove one or more completion handlers for the given request identifier
 */
DWORD packet_remove_completion_handler(LPCSTR requestId)
{
	PacketCompletionRoutineEntry *current, *next, *prev;

	// Enumerate the list, removing entries that match
	for (current = packetCompletionRoutineList, next = NULL, prev = NULL;
	     current;
		  prev = current, current = next)
	{
		next = current->next;

		if (strcmp(requestId, current->requestId))
			continue;

		// Remove the entry from the list
		if (prev)
			prev->next = next;
		else
			packetCompletionRoutineList = next;
	
		// Deallocate it
		free((PCHAR)current->requestId);
		free(current);
	}

	return ERROR_SUCCESS;
}

/*
 * Transmit and destroy a packet
 */
DWORD packet_transmit(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	if (remote->transport == METERPRETER_TRANSPORT_SSL) {
		return packet_transmit_via_ssl(remote, packet, completion);
	}
	if (remote->transport == METERPRETER_TRANSPORT_HTTP || remote->transport == METERPRETER_TRANSPORT_HTTPS) {
		return packet_transmit_via_http(remote, packet, completion);
	}
	return 0;
}

/*
 * Transmit and destroy a packet over SSL
 */
DWORD packet_transmit_via_ssl(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	CryptoContext *crypto;
	Tlv requestId;
	DWORD res;
	DWORD idx;
#ifdef _UNIX
	int local_error = -1;
#endif

	lock_acquire( remote->lock );

	// If the packet does not already have a request identifier, create one for it
	if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,&requestId) != ERROR_SUCCESS)
	{
		DWORD index;
		CHAR rid[32];

		rid[sizeof(rid) - 1] = 0;

		for (index = 0; index < sizeof(rid) - 1; index++)
			rid[index] = (rand() % 0x5e) + 0x21;

		packet_add_tlv_string(packet, TLV_TYPE_REQUEST_ID, rid);
	}

	do
	{
		// If a completion routine was supplied and the packet has a request 
		// identifier, insert the completion routine into the list
		if ((completion) &&
		    (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,
				&requestId) == ERROR_SUCCESS))
			packet_add_completion_handler((LPCSTR)requestId.buffer, completion);

		// If the endpoint has a cipher established and this is not a plaintext
		// packet, we encrypt
		if ((crypto = remote_get_cipher(remote)) &&
		    (packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
		    (packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = packet->payloadLength;
			PUCHAR origPayload = packet->payload;

			// Encrypt
			if ((res = crypto->handlers.encrypt(crypto, packet->payload, 
					packet->payloadLength, &packet->payload, 
					&packet->payloadLength)) !=
					ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// Destroy the original payload as we no longer need it
			free(origPayload);

			// Update the header length
			packet->header.length = htonl(packet->payloadLength + sizeof(TlvHeader));
		}

		idx = 0;
		while( idx < sizeof(packet->header))
		{ 
			// Transmit the packet's header (length, type)
			res = SSL_write(
				remote->ssl, 
				(LPCSTR)(&packet->header) + idx, 
				sizeof(packet->header) - idx
			);
			
			if(res <= 0) {
				dprintf("[PACKET] transmit header failed with return %d at index %d\n", res, idx);
				break;
			}
			idx += res;
		}

		if(res < 0)
			break;

		idx = 0;
		while( idx < packet->payloadLength)
		{ 
			// Transmit the packet's payload (length, type)
			res = SSL_write(
				remote->ssl, 
				packet->payload + idx,
				packet->payloadLength - idx
			);
			if(res < 0)
				break;

			idx += res;
		}

		if(res < 0) {
			dprintf("[PACKET] transmit header failed with return %d at index %d\n", res, idx);
			break;
		}

		SetLastError(ERROR_SUCCESS);
	} while (0);

	res = GetLastError();

	// Destroy the packet
	packet_destroy(packet);

	lock_release( remote->lock );

	return res;
}



/*
 * Transmit and destroy a packet over HTTP(S)
 */
DWORD packet_transmit_via_http(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	CryptoContext *crypto;
	Tlv requestId;
	DWORD res;
#ifdef _UNIX
	int local_error = -1;
#endif


	lock_acquire( remote->lock );

	// If the packet does not already have a request identifier, create one for it
	if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,&requestId) != ERROR_SUCCESS)
	{
		DWORD index;
		CHAR rid[32];

		rid[sizeof(rid) - 1] = 0;

		for (index = 0; index < sizeof(rid) - 1; index++)
			rid[index] = (rand() % 0x5e) + 0x21;

		packet_add_tlv_string(packet, TLV_TYPE_REQUEST_ID, rid);
	}

	do
	{
		// If a completion routine was supplied and the packet has a request 
		// identifier, insert the completion routine into the list
		if ((completion) &&
		    (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,
				&requestId) == ERROR_SUCCESS))
			packet_add_completion_handler((LPCSTR)requestId.buffer, completion);

		// If the endpoint has a cipher established and this is not a plaintext
		// packet, we encrypt
		if ((crypto = remote_get_cipher(remote)) &&
		    (packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
		    (packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = packet->payloadLength;
			PUCHAR origPayload = packet->payload;

			// Encrypt
			if ((res = crypto->handlers.encrypt(crypto, packet->payload, 
					packet->payloadLength, &packet->payload, 
					&packet->payloadLength)) !=
					ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// Destroy the original payload as we no longer need it
			free(origPayload);

			// Update the header length
			packet->header.length = htonl(packet->payloadLength + sizeof(TlvHeader));
		}

#ifdef _WIN32
		dprintf("Transmitting packet of length %d to remote", packet->payloadLength);
		res = packet_transmit_via_http_wininet(remote, packet, completion);
#else
		// XXX: Implement non-windows HTTP delivery
#endif

		if(res < 0) {
			dprintf("[PACKET] transmit failed with return %d\n", res);
			break;
		}

		SetLastError(ERROR_SUCCESS);
	} while (0);

	res = GetLastError();

	// Destroy the packet
	packet_destroy(packet);

	lock_release( remote->lock );

	return res;
}


/*
 * Transmit and destroy a packet over HTTP(S)
 */
#ifdef _WIN32
DWORD packet_transmit_via_http_wininet(Remote *remote, Packet *packet, PacketRequestCompletion *completion) {
	DWORD res = 0;
	HINTERNET hReq;
	HINTERNET hRes;
	DWORD retries = 5;
	DWORD flags;
	DWORD flen;
	unsigned char *buffer;

	flen = sizeof(flags);

	buffer = malloc( packet->payloadLength + sizeof(TlvHeader) );
	if (! buffer) {
		SetLastError(ERROR_NOT_FOUND);
		return 0;
	}

	memcpy(buffer, &packet->header, sizeof(TlvHeader));
	memcpy(buffer + sizeof(TlvHeader), packet->payload, packet->payloadLength);

	do {

		flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI;
		if (remote->transport == METERPRETER_TRANSPORT_HTTPS) {
			flags |= INTERNET_FLAG_SECURE |  INTERNET_FLAG_IGNORE_CERT_CN_INVALID  | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
		}

		hReq = HttpOpenRequest(remote->hConnection, "POST", remote->uri, NULL, NULL, NULL, flags, 0);

		if (hReq == NULL) {
			dprintf("[PACKET RECEIVE] Failed HttpOpenRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		if (remote->transport == METERPRETER_TRANSPORT_HTTPS) {
			InternetQueryOption( hReq, INTERNET_OPTION_SECURITY_FLAGS, &flags, &flen);
			flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
			InternetSetOption(hReq, INTERNET_OPTION_SECURITY_FLAGS, &flags, flen);
		}

		hRes = HttpSendRequest(hReq, NULL, 0, buffer, packet->payloadLength + sizeof(TlvHeader) );

		if (! hRes) {
			dprintf("[PACKET RECEIVE] Failed HttpSendRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}
	} while(0);

	memset(buffer, 0, packet->payloadLength + sizeof(TlvHeader));
	InternetCloseHandle(hReq);
	return res;
}

#endif

/*
 * Transmits a response with nothing other than a result code in it
 */
DWORD packet_transmit_empty_response(Remote *remote, Packet *packet, DWORD res)
{
	Packet *response = packet_create_response(packet);

	if (!response)
		return ERROR_NOT_ENOUGH_MEMORY;

	// Add the result code
	packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

	// Transmit the response
	return packet_transmit(remote, response, NULL);
}

/*
 * Receive a new packet
 */
DWORD packet_receive(Remote *remote, Packet **packet)
{
	DWORD headerBytes = 0, payloadBytesLeft = 0, res; 
	CryptoContext *crypto = NULL;
	Packet *localPacket = NULL;
	TlvHeader header;
	LONG bytesRead;
	BOOL inHeader = TRUE;
	PUCHAR payload = NULL;
	ULONG payloadLength;

#ifdef _UNIX
	int local_error = -1;
#endif

	
	if (remote->transport == METERPRETER_TRANSPORT_HTTP || remote->transport == METERPRETER_TRANSPORT_HTTPS)
		return packet_receive_via_http(remote, packet);
	
	
	lock_acquire( remote->lock );

	do
	{
		// Read the packet length
		while (inHeader)
		{
			if ((bytesRead = SSL_read(remote->ssl, ((PUCHAR)&header + headerBytes), sizeof(TlvHeader) - headerBytes)) <= 0)
			{
				if (!bytesRead)
					SetLastError(ERROR_NOT_FOUND);

				if(bytesRead < 0) {
					dprintf("[PACKET] receive header failed with error code %d. SSLerror=%d, WSALastError=%d\n", bytesRead, SSL_get_error( remote->ssl, bytesRead ), WSAGetLastError() );
					SetLastError(ERROR_NOT_FOUND);
				}

				break;
			}

			headerBytes += bytesRead;
	
			if (headerBytes != sizeof(TlvHeader))
				continue;
			else
				inHeader = FALSE;
		}
		
		if (headerBytes != sizeof(TlvHeader))
			break;

		// Initialize the header
		header.length    = header.length;
		header.type      = header.type;
		payloadLength    = ntohl(header.length) - sizeof(TlvHeader);
		payloadBytesLeft = payloadLength;

		// Allocate the payload
		if (!(payload = (PUCHAR)malloc(payloadLength)))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}
			
		// Read the payload
		while (payloadBytesLeft > 0)
		{
			if ((bytesRead = SSL_read(remote->ssl, payload + payloadLength - payloadBytesLeft, payloadBytesLeft)) <= 0)
			{

				if (GetLastError() == WSAEWOULDBLOCK)
					continue;

				if (!bytesRead)
					SetLastError(ERROR_NOT_FOUND);

				if(bytesRead < 0) {
					dprintf("[PACKET] receive payload of length %d failed with error code %d. SSLerror=%d\n", payloadLength, bytesRead, SSL_get_error( remote->ssl, bytesRead ) );
					SetLastError(ERROR_NOT_FOUND);
				}

				break;
			}

			payloadBytesLeft -= bytesRead;
		}
		
		// Didn't finish?
		if (payloadBytesLeft)
			break;

		// Allocate a packet structure
		if (!(localPacket = (Packet *)malloc(sizeof(Packet))))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		memset( localPacket, 0, sizeof(Packet) );

		// If the connection has an established cipher and this packet is not
		// plaintext, decrypt
		if ((crypto = remote_get_cipher(remote)) &&
		    (packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
		    (packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = payloadLength;
			PUCHAR origPayload = payload;

			// Decrypt
			if ((res = crypto->handlers.decrypt(crypto, payload, payloadLength,&payload, &payloadLength)) != ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// We no longer need the encrypted payload
			free(origPayload);
		}

		localPacket->header.length = header.length;
		localPacket->header.type   = header.type;
		localPacket->payload       = payload;
		localPacket->payloadLength = payloadLength;

		*packet = localPacket;

		SetLastError(ERROR_SUCCESS);

	} while (0);

	res = GetLastError();

	// Cleanup on failure
	if (res != ERROR_SUCCESS)
	{
		if (payload)
			free(payload);
		if (localPacket)
			free(localPacket);
	}

	lock_release( remote->lock );

	return res;
}


#ifdef _WIN32
/*
 * Receive a new packet over HTTP using WinInet
 */
DWORD packet_receive_http_via_wininet(Remote *remote, Packet **packet) {

	DWORD headerBytes = 0, payloadBytesLeft = 0, res; 
	CryptoContext *crypto = NULL;
	Packet *localPacket = NULL;
	TlvHeader header;
	LONG bytesRead;
	BOOL inHeader = TRUE;
	PUCHAR payload = NULL;
	ULONG payloadLength;
	DWORD flags;
	DWORD flen;

	HINTERNET hReq;
	HINTERNET hRes;
	DWORD retries = 5;
	
	lock_acquire( remote->lock );

	do {

		flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI;
		if (remote->transport == METERPRETER_TRANSPORT_HTTPS) {
			flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
		}
		dprintf("[PACKET RECEIVE] HttpOpenRequest");
		hReq = HttpOpenRequest(remote->hConnection, "POST", remote->uri, NULL, NULL, NULL, flags, 0);

		if (hReq == NULL) {
			dprintf("[PACKET RECEIVE] Failed HttpOpenRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		if (remote->transport == METERPRETER_TRANSPORT_HTTPS) {
			InternetQueryOption( hReq, INTERNET_OPTION_SECURITY_FLAGS, &flags, &flen);
			flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
			InternetSetOption(hReq, INTERNET_OPTION_SECURITY_FLAGS, &flags, flen);
		}
		
		hRes = HttpSendRequest(hReq, NULL, 0, "RECV", 4 );
		if (! hRes) {
			dprintf("[PACKET RECEIVE] Failed HttpSendRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		// Read the packet length
		retries = 3;
		while (inHeader && retries > 0)
		{
			retries--;
			if (! InternetReadFile(hReq, ((PUCHAR)&header + headerBytes), sizeof(TlvHeader) - headerBytes, &bytesRead))  {
				dprintf("[PACKET RECEIVE] Failed HEADER InternetReadFile: %d", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			headerBytes += bytesRead;
	
			if (headerBytes != sizeof(TlvHeader)) {
				if (bytesRead == 0) {
					SetLastError(ERROR_NOT_FOUND);
					break;
				}
				continue;
			} else {
				inHeader = FALSE;
			}
		}
		
		if (headerBytes != sizeof(TlvHeader)) {
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		// Initialize the header
		header.length    = header.length;
		header.type      = header.type;
		payloadLength    = ntohl(header.length) - sizeof(TlvHeader);
		payloadBytesLeft = payloadLength;

		// Allocate the payload
		if (!(payload = (PUCHAR)malloc(payloadLength)))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}
			
		// Read the payload
		retries = payloadBytesLeft;
		while (payloadBytesLeft > 0 && retries > 0 )
		{
			retries--;
			if (! InternetReadFile(hReq, payload + payloadLength - payloadBytesLeft, payloadBytesLeft, &bytesRead))  {
				dprintf("[PACKET RECEIVE] Failed BODY InternetReadFile: %d", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			if (!bytesRead) {
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			payloadBytesLeft -= bytesRead;
		}
		
		// Didn't finish?
		if (payloadBytesLeft)
			break;

		// Allocate a packet structure
		if (!(localPacket = (Packet *)malloc(sizeof(Packet))))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		memset( localPacket, 0, sizeof(Packet) );

		// If the connection has an established cipher and this packet is not
		// plaintext, decrypt
		if ((crypto = remote_get_cipher(remote)) &&
		    (packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
		    (packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = payloadLength;
			PUCHAR origPayload = payload;

			// Decrypt
			if ((res = crypto->handlers.decrypt(crypto, payload, payloadLength,&payload, &payloadLength)) != ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// We no longer need the encrypted payload
			free(origPayload);
		}

		localPacket->header.length = header.length;
		localPacket->header.type   = header.type;
		localPacket->payload       = payload;
		localPacket->payloadLength = payloadLength;

		*packet = localPacket;

		SetLastError(ERROR_SUCCESS);

	} while (0);

	res = GetLastError();

	// Cleanup on failure
	if (res != ERROR_SUCCESS)
	{
		if (payload)
			free(payload);
		if (localPacket)
			free(localPacket);
	}

	if (hReq) 
		InternetCloseHandle(hReq);

	lock_release( remote->lock );

	return res;
}

#endif



/*
 * Receive a new packet over HTTP
 */
#ifdef _WIN32

DWORD packet_receive_via_http(Remote *remote, Packet **packet)
{
	return packet_receive_http_via_wininet(remote, packet);
}

#else

DWORD packet_receive_via_http(Remote *remote, Packet **packet)
{
	return 0;
}

#endif