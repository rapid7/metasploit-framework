#ifndef _METERPRETER_BASE_H
#define _METERPRETER_BASE_H

#include "linkage.h"
#include "core.h"

/*
 * Command dispatch table types
 */
typedef DWORD (*DISPATCH_ROUTINE)(Remote *remote, Packet *packet);

#define MAX_CHECKED_ARGUMENTS  16

#define ARGUMENT_FLAG_REPEAT   (1 << 28)
#define ARGUMENT_FLAG_MASK     0x0fffffff

// Blank dispatch handler
#define EMPTY_DISPATCH_HANDLER NULL, { 0 }, 0

// Place holders
#define EXPORT_TABLE_BEGIN()
#define EXPORT_TABLE_END()

typedef struct 
{
	DISPATCH_ROUTINE    handler;

	TlvMetaType         argumentTypes[MAX_CHECKED_ARGUMENTS];
	DWORD               numArgumentTypes;
} PacketDispatcher;

typedef struct command
{
	LPCSTR           method; 
	PacketDispatcher request;
	PacketDispatcher response;

	// Internal -- not stored
	struct command   *next;
	struct command   *prev;
} Command;

LINKAGE DWORD command_register(Command *command);
LINKAGE DWORD command_deregister(Command *command);

LINKAGE VOID command_join_threads( VOID );

LINKAGE DWORD THREADCALL command_process_thread( THREAD * thread );
//LINKAGE DWORD command_process_remote(Remote *remote, Packet *inPacket);
//LINKAGE DWORD command_process_remote_loop(Remote *remote);

LINKAGE DWORD command_call_dispatch(Command *command, Remote *remote, Packet *packet);
LINKAGE DWORD command_validate_arguments(Command *command, Packet *packet);

#endif
