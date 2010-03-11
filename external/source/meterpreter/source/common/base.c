#include "common.h"

// Local remote request implementors
extern DWORD remote_request_core_console_write(Remote *remote, Packet *packet);

extern DWORD remote_request_core_channel_open(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_write(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_read(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_close(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_seek(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_eof(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_tell(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_interact(Remote *remote, Packet *packet);

extern DWORD remote_request_core_crypto_negotiate(Remote *remote, Packet *packet);

extern DWORD remote_request_core_migrate(Remote *remote, Packet *packet);

// Local remote response implementors
extern DWORD remote_response_core_console_write(Remote *remote, Packet *packet);

extern DWORD remote_response_core_channel_open(Remote *remote, Packet *packet);
extern DWORD remote_response_core_channel_close(Remote *remote, Packet *packet);

DWORD remote_request_core_console_write(Remote *remote, Packet *packet)
{
	return ERROR_SUCCESS;
}

DWORD remote_response_core_console_write(Remote *remote, Packet *packet)
{
	return ERROR_SUCCESS;
}



/*
 * Base RPC dispatch table
 */
Command commands[] =
{
	/*
	 * Core commands
	 */

	// Console commands
	{  "core_console_write",  
		{ remote_request_core_console_write,     { TLV_META_TYPE_STRING }, 1 | ARGUMENT_FLAG_REPEAT },
		{ remote_response_core_console_write,    { 0 },  0 },
	},

	// Native Channel commands
	{  "core_channel_open",
		{ remote_request_core_channel_open,      { 0 },  0 },	
		{ remote_response_core_channel_open,     { 0 },  0 },
	},
	{  "core_channel_write",
		{ remote_request_core_channel_write,     { 0 },  0 },	
		{ EMPTY_DISPATCH_HANDLER                           },
	},
	{  "core_channel_close",
		{ remote_request_core_channel_close,     { 0 },  0 },	
		{ remote_response_core_channel_close,    { 0 },  0 },	
	},

	// Buffered/Pool channel commands
	{  "core_channel_read",
		{ remote_request_core_channel_read,      { 0 },  0 },	
		{ EMPTY_DISPATCH_HANDLER                           },
	},
	// Pool channel commands
	{  "core_channel_seek",
		{ remote_request_core_channel_seek,      { 0 },  0 },	
		{ EMPTY_DISPATCH_HANDLER                           },
	},
	{  "core_channel_eof",
		{ remote_request_core_channel_eof,       { 0 },  0 },	
		{ EMPTY_DISPATCH_HANDLER                           },
	},
	{  "core_channel_tell",
		{ remote_request_core_channel_tell,      { 0 },  0 },	
		{ EMPTY_DISPATCH_HANDLER                           },
	},

	// Soon to be deprecated
	{  "core_channel_interact",
		{ remote_request_core_channel_interact,  { 0 },  0 },	
		{ EMPTY_DISPATCH_HANDLER                           },
	},

	// Crypto
	{  "core_crypto_negotiate",
	   { remote_request_core_crypto_negotiate,  { 0 },  0 },
		{ EMPTY_DISPATCH_HANDLER                           },
	},

	// Migration
	{  "core_migrate",
	   { remote_request_core_migrate,           { 0 },  0 },
		{ EMPTY_DISPATCH_HANDLER                           },
	},

	// Terminator
	{  NULL,
		{ NULL, { 0 }, 0 },
		{ NULL, { 0 }, 0 },
	},
};

// Dynamically registered command extensions
Command *extensionList = NULL;

/*
 * Dynamically register a custom command handler
 */
DWORD command_register(Command *command)
{
	Command *newCommand;

	if (!(newCommand = (Command *)malloc(sizeof(Command))))
		return ERROR_NOT_ENOUGH_MEMORY;

	memcpy(newCommand, command, sizeof(Command));

	if (extensionList)
		extensionList->prev = newCommand;

	newCommand->next    = extensionList;
	newCommand->prev    = NULL;
	extensionList       = newCommand;
			
	return ERROR_SUCCESS;
}

/*
 * Dynamically deregister a custom command handler
 */
DWORD command_deregister(Command *command)
{
	Command *current, *prev;
	DWORD res = ERROR_NOT_FOUND;
	
	// Search the extension list for the command
	for (current = extensionList, prev = NULL;
	     current;
	     prev = current, current = current->next)
	{
		if (strcmp(command->method, current->method))
			continue;

		if (prev)
			prev->next = current->next;
		else
			extensionList = current->next;

		if (current->next)
			current->next->prev = prev;

		// Deallocate it
		free(current);
		
		res = ERROR_SUCCESS;

		break;
	}

	return res;
}

/*
 * A list of all command threads currenlty executing.
 */
LIST * commandThreadList = NULL;

/*
 * Block untill all running command threads have finished.
 */
VOID command_join_threads( VOID )
{
	while( list_count( commandThreadList ) > 0 )
	{
		THREAD * thread = (THREAD *)list_get( commandThreadList, 0 );
		if( thread )
			thread_join( thread );
	}
}

/*
 * Crude method of throttling the ammount of concurrent command 
 * threads we allow in the system at a given time.
 */
/*
VOID command_throtle( int maxthreads )
{
	while( list_count( commandThreadList ) >= maxthreads )
	{
		Sleep( 250 );
	}
}
*/

/*
 * Process a single command in a seperate thread of execution.
 */
DWORD THREADCALL command_process_thread( THREAD * thread )
{
	DWORD index       = 0;
	DWORD result      = ERROR_SUCCESS;
	Tlv methodTlv     = {0};
	Tlv requestIdTlv  = {0};
	PCHAR method      = NULL;
	PCHAR requestId   = NULL;
	Command * current = NULL;
	Remote * remote   = NULL;
	Packet * packet   = NULL;
	
	if( thread == NULL )
		return ERROR_INVALID_HANDLE;

	remote = (Remote *)thread->parameter1;
	if( remote == NULL )
		return ERROR_INVALID_HANDLE;
	
	packet = (Packet *)thread->parameter2;
	if( packet == NULL )
		return ERROR_INVALID_DATA;

	if( commandThreadList == NULL )
	{
		commandThreadList = list_create();
		if( commandThreadList == NULL )
			return ERROR_INVALID_HANDLE;
	}

	list_add( commandThreadList, thread );

	__try
	{
		do
		{

			// Extract the method
			result = packet_get_tlv_string( packet, TLV_TYPE_METHOD, &methodTlv );
			if( result != ERROR_SUCCESS )
				break;

			dprintf( "[COMMAND] Processing method %s", methodTlv.buffer );

			// Impersonate the thread token if needed
			if(remote->hServerToken != remote->hThreadToken) {
				if(! ImpersonateLoggedOnUser(remote->hThreadToken)) {
					dprintf( "[COMMAND] Failed to impersonate thread token (%s) (%u)", methodTlv.buffer, GetLastError());
				}
			}
			
			// Get the request identifier if the packet has one.
			result = packet_get_tlv_string( packet, TLV_TYPE_REQUEST_ID, &requestIdTlv );
			if( result == ERROR_SUCCESS )
				requestId = (PCHAR)requestIdTlv.buffer;

			method = (PCHAR)methodTlv.buffer;

			result = ERROR_NOT_FOUND;

			// Try to find a match in the dispatch type
			for( index = 0, result = ERROR_NOT_FOUND ; result == ERROR_NOT_FOUND && commands[index].method ; index++ )
			{
				if( strcmp( commands[index].method, method ) )
					continue;

				// Call the base handler
				result = command_call_dispatch( &commands[index], remote, packet );
			}

			// Regardless of error code, try to see if someone has overriden a base handler
			for( current = extensionList, result = ERROR_NOT_FOUND ; 
				  result == ERROR_NOT_FOUND && current && current->method ; current = current->next )
			{
				if( strcmp( current->method, method ) )
					continue;
			
				// Call the custom handler
				result = command_call_dispatch( current, remote, packet );
			}

			dprintf("[COMMAND] Calling completion handlers...");
			// Finally, call completion routines for the provided identifier
			if( ((packet_get_type(packet) == PACKET_TLV_TYPE_RESPONSE) || (packet_get_type(packet) == PACKET_TLV_TYPE_PLAIN_RESPONSE)) && (requestId))
				packet_call_completion_handlers( remote, packet, requestId );

			// If we get here, we're successful.
			result = ERROR_SUCCESS;
			
		} while( 0 );
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		dprintf("[COMMAND] Exception hit in command thread 0x%08X!", thread );
	}

	packet_destroy( packet );

	if( list_remove( commandThreadList, thread ) )
		thread_destroy( thread );

	return ERROR_SUCCESS;
}

/*
 * Process a single command
 */
/*
DWORD command_process_remote(Remote *remote, Packet *inPacket)
{
	DWORD res = ERROR_SUCCESS, index;
	Tlv methodTlv, requestIdTlv;
	Packet *localPacket = NULL;
	PCHAR method, requestId = NULL;
	Command *current;

	do
	{
		// If no packet was providied, try to receive one.
		if (!inPacket)
		{
			if ((res = packet_receive(remote, &localPacket)) != ERROR_SUCCESS)
				break;
			else
				inPacket = localPacket;
		}

		// Extract the method
		if ((packet_get_tlv_string(inPacket, TLV_TYPE_METHOD, &methodTlv)
				!= ERROR_SUCCESS))
			break;
		dprintf("Processing method %s", methodTlv.buffer);

		// Get the request identifier if the packet has one.
		if (packet_get_tlv_string(inPacket, TLV_TYPE_REQUEST_ID, 
				&requestIdTlv) == ERROR_SUCCESS)
			requestId = (PCHAR)requestIdTlv.buffer;

		method = (PCHAR)methodTlv.buffer;

		res = ERROR_NOT_FOUND;

		// Try to find a match in the dispatch type
		for (index = 0, res = ERROR_NOT_FOUND; 
			  res = ERROR_NOT_FOUND && commands[index].method; 
			  index++)
		{
			if (strcmp(commands[index].method, method))
				continue;

			// Call the base handler
			res = command_call_dispatch(&commands[index], remote, inPacket);
		}

		// Regardless of error code, try to see if someone has overriden
		// a base handler
		for (current = extensionList, res = ERROR_NOT_FOUND; 
			  res == ERROR_NOT_FOUND && current && current->method; 
			  current = current->next)
		{
			if (strcmp(current->method, method))
				continue;
		
			// Call the custom handler
			res = command_call_dispatch(current, remote, inPacket);
		}

		dprintf("Calling completion handlers...");
		// Finally, call completion routines for the provided identifier
		if (((packet_get_type(inPacket) == PACKET_TLV_TYPE_RESPONSE) ||
		     (packet_get_type(inPacket) == PACKET_TLV_TYPE_PLAIN_RESPONSE)) &&
		    (requestId))
			packet_call_completion_handlers(remote, inPacket, requestId);

		// If we get here, we're successful.
		res = ERROR_SUCCESS;
		
	} while (0);

	if (localPacket)
		packet_destroy(localPacket);

	return res;
}*/

/*
 * Process incoming commands, calling dispatch tables appropriately
 */ 
/*
DWORD command_process_remote_loop(Remote *remote)
{
	DWORD res = ERROR_SUCCESS;
	Packet *packet;

	while ((res = packet_receive(remote, &packet)) == ERROR_SUCCESS)
	{
		res = command_process_remote(remote, packet);

		// Destroy the packet
		packet_destroy(packet);
	
		// If a command returned exit, we shall return.
		if (res == ERROR_INSTALL_USEREXIT)
			break;
	}

	return res;
}
*/

/*
 * Call the dispatch routine for a given command
 */
DWORD command_call_dispatch(Command *command, Remote *remote, Packet *packet)
{
	DWORD res;

	// Validate the arguments, if requested.  Always make sure argument 
	// lengths are sane.
	if ((res = command_validate_arguments(command, packet)) != ERROR_SUCCESS)
		return res;

	switch (packet_get_type(packet))
	{
		case PACKET_TLV_TYPE_REQUEST:
		case PACKET_TLV_TYPE_PLAIN_REQUEST:
			if (command->request.handler)
				res = command->request.handler(remote, packet);
			break;
		case PACKET_TLV_TYPE_RESPONSE:
		case PACKET_TLV_TYPE_PLAIN_RESPONSE:
			if (command->response.handler)
				res = command->response.handler(remote, packet);
			break;
		default:
			res = ERROR_NOT_FOUND;
			break;
	}

	return res;
}

/*
 * Validate command arguments
 */
DWORD command_validate_arguments(Command *command, Packet *packet)
{
	PacketDispatcher *dispatcher = NULL;
	PacketTlvType type = packet_get_type(packet);
	DWORD res = ERROR_SUCCESS, 
		packetIndex, commandIndex;
	Tlv current;

	// Select the dispatcher table
	if ((type == PACKET_TLV_TYPE_RESPONSE) ||
	    (type == PACKET_TLV_TYPE_PLAIN_RESPONSE))
		dispatcher = &command->response;
	else
		dispatcher = &command->request;

	// Enumerate the arguments, validating the meta types of each
	for (commandIndex = 0, packetIndex = 0;
	     ((packet_enum_tlv(packet, packetIndex, TLV_TYPE_ANY, &current) 
			 == ERROR_SUCCESS) &&
	      (res == ERROR_SUCCESS));
	     commandIndex++, packetIndex++)
	{
		TlvMetaType tlvMetaType;

		// Check to see if we've reached the end of the command arguments
		if ((dispatcher->numArgumentTypes) &&
		    (commandIndex == (dispatcher->numArgumentTypes & ARGUMENT_FLAG_MASK)))
		{
			// If the repeat flag is set, reset the index
			if (commandIndex & ARGUMENT_FLAG_REPEAT)
				commandIndex = 0;
			else
				break;
		}
		
		// Make sure the argument is at least one of the meta types
		tlvMetaType = packet_get_tlv_meta(packet, &current);

		// Validate argument meta types
		switch (tlvMetaType)
		{
			case TLV_META_TYPE_STRING:
				if (packet_is_tlv_null_terminated(packet, &current) != ERROR_SUCCESS)
					res = ERROR_INVALID_PARAMETER;
				break;
			default:
				break;
		}
	
		if ((res != ERROR_SUCCESS) && 
		    (commandIndex < dispatcher->numArgumentTypes))
			break;
	}

	return res;
}
