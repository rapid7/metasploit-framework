#ifndef _METERPRETER_CLIENT_CONSOLE_H
#define _METERPRETER_CLIENT_CONSOLE_H

#define OUTBOUND_PREFIX ">>>"
#define INBOUND_PREFIX  "<<<"

VOID console_initialize();

/*
 * Output processing
 */
LINKAGE VOID console_write_output(LPCSTR fmt, ...);
LINKAGE VOID console_write_output_raw(PUCHAR buf, ULONG length);
LINKAGE VOID console_write_prompt();

LINKAGE DWORD console_generic_response_output(Remote *remote, Packet *packet,
		LPCSTR subsys, LPCSTR cmd);

/*
 * Interact channel
 */
LINKAGE VOID console_set_interactive_channel(Remote *remote, Channel *channel);
LINKAGE Channel *console_get_interactive_channel();
LINKAGE DWORD console_get_interactive_channel_id();

/*
 * Input processing
 */
typedef struct _ConsoleCommand
{
	LPCSTR                 name;
	DWORD                  (*handler)(Remote *remote, UINT argc, CHAR **argv);
	LPCSTR                 help;
	BOOL                   separator;

	// Not stored
	struct _ConsoleCommand *prev;	
	struct _ConsoleCommand *next;	
} ConsoleCommand;

LINKAGE VOID console_read_buffer(Remote *remote);
LINKAGE VOID console_process_command(Remote *remote);
LINKAGE VOID console_process_commands(Remote *remote);

LINKAGE DWORD console_register_command(ConsoleCommand *command);
LINKAGE DWORD console_deregister_command(ConsoleCommand *command);

LINKAGE VOID console_register_core_commands();
LINKAGE VOID console_deregister_core_commands();

LINKAGE BOOL console_check_escape_sent();

#endif
