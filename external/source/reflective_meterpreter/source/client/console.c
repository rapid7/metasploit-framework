#include "metcli.h"

// Core console commands
extern DWORD cmd_open(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_read(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_write(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_close(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_interact(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_help(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_exit(Remote *remote, UINT argc, CHAR **argv);

extern DWORD cmd_loadlib(Remote *remote, UINT argc, CHAR **argv);
extern DWORD cmd_use(Remote *remote, UINT argc, CHAR **argv);

/*
 * Local client core command line dispatch table
 */
ConsoleCommand consoleCommands[] =
{
	// Core extensions
	{ "Core",     NULL,         "Core feature set commands",                           1 },
	{ "open",     cmd_open,     "Opens a communication channel.",                      0 },
	{ "read",     cmd_read,     "Reads from a communication channel.",                 0 },
	{ "write",    cmd_write,    "Writes to a communication channel.",                  0 },
	{ "close",    cmd_close,    "Closes a communication channel.",                     0 },
	{ "interact", cmd_interact, "Switch to interactive mode with a channel.",          0 },
	{ "help",     cmd_help,     "Displays a list of commands.",                        0 },
	{ "exit",     cmd_exit,     "Exits the client.",                                   0 },

	// Feature extensions
	{ "Features", NULL,         "Feature extension commands",                          1 },
	{ "loadlib",  cmd_loadlib,  "Load a library on the remote machine.",               0 },
	{ "use",      cmd_use,      "Use a feature module.",                               0 },

	// Terminator
	{ NULL,       NULL,         NULL,                                                  0 },
};

VOID console_read_thread_func(Remote *remote);

ConsoleCommand *extendedCommandsHead = NULL;
ConsoleCommand *extendedCommandsTail = NULL;
Channel *interactiveChannel          = NULL;
DWORD interactiveChannelId           = 0;
PCHAR inputBuffer                    = NULL;
ULONG inputBufferLength              = 0;
HANDLE consoleReadThread             = NULL;

#ifdef _WIN32

/*
 * Enable command history on the console and create the interactive console
 * for future use.
 */
VOID console_initialize(Remote *remote)
{
	BOOL (WINAPI *setConsoleInputExeName)(LPCSTR base) = NULL;
	CHAR name[1024];
	PCHAR slash;
	float init = 1.1f; // VC++ requires float usage to use float libraries.
	DWORD mode = 0;
	DWORD tid;

	do
	{
		// Locate the SetConsoleInputExeNameA routine for use with custom
		// history tracking
		if (!((LPVOID)setConsoleInputExeName = 
				(LPVOID)GetProcAddress(GetModuleHandle("kernel32"), 
					"SetConsoleInputExeNameA")))
			break;

		memset(name, 0, sizeof(name));

		if (!GetModuleFileName(
				GetModuleHandle(0), 
				name,
				sizeof(name) - 1))
			break;

		if (!(slash = strrchr(name, '\\')))
			break;

		// investigate
		setConsoleInputExeName(name);

		// Set the console window's title
		SetConsoleTitle("meterpreter");
	
		consoleReadThread = CreateThread(NULL, 0, 
				(LPTHREAD_START_ROUTINE)console_read_thread_func, remote,
				0, &tid);
	
	} while (0);
}

/*
 * Write a format string buffer to the console
 */
VOID console_write_output(LPCSTR fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

/*
 * Write raw output to the console
 */
VOID console_write_output_raw(PUCHAR buf, ULONG length)
{
	HANDLE pStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD written = 0;

	WriteFile(pStdout, buf, length, &written, NULL);
}

/*
 * Write the console prompt to the screen
 */
VOID console_write_prompt()
{
	fprintf(stdout, "meterpreter> ");
	fflush(stdout);
}

/*
 * Generic output of success/fail
 */
DWORD console_generic_response_output(Remote *remote, Packet *packet,
		LPCSTR subsys, LPCSTR cmd)
{
	DWORD res = packet_get_result(packet);

	if (res == ERROR_SUCCESS)
		console_write_output(
				"\n"
				INBOUND_PREFIX " %s: %s succeeded.\n", subsys, cmd);
	else
		console_write_output(
				"\n"
				INBOUND_PREFIX " %s: %s failed, result %lu.\n", 
				subsys, cmd, packet_get_result(packet));

	console_write_prompt();

	return res;
}

/*
 * Check to see if an escape sequence has been sent to the console
 *
 * The escape sequence is: ESC
 */
BOOL console_check_escape_sent()
{
	BOOL escapeSent = FALSE;
	INPUT_RECORD r[32];
	DWORD numRead = 0;

	if (PeekConsoleInput(GetStdHandle(STD_INPUT_HANDLE),
			r, 32, &numRead))
	{
		DWORD index = 0;

		for (index = 0;
		     (!escapeSent) && (index < numRead);
		     index++)
		{
			if (r[index].EventType != KEY_EVENT)
				continue;

			// If the control key is pressed and the VK is escape..
			if (r[index].Event.KeyEvent.wVirtualKeyCode == VK_ESCAPE)
				escapeSent = TRUE;
		}
	}

	return escapeSent;
}

#endif

/*
 * Set the interactive channel for input/output overriding
 */
VOID console_set_interactive_channel(Remote *remote, Channel *channel)
{
	// If an interactive channel is use, unset the interactive flag
	if (interactiveChannel)
		channel_interact(interactiveChannel, remote, NULL, 0, FALSE,
				NULL);

	interactiveChannel   = channel;
	interactiveChannelId = (channel) ? channel_get_id(channel) : 0;
}

/*
 * Get the interactive channel descriptor
 */
Channel *console_get_interactive_channel()
{
	return interactiveChannel;
}

/*
 * Get the interactive channel indentifier, if any
 */
DWORD console_get_interactive_channel_id()
{
	return interactiveChannelId;
}

/*
 * Process a remote cmomand when data is available
 */
DWORD console_remote_notify(Remote *remote, HANDLE notify)
{
	DWORD res;

	ResetEvent(notify);

	res = command_process_remote(remote, NULL);

	return res;
}

/*
 * Process console commands in a loop
 *
 * I would use the scheduler but allowing the file descriptor to drop
 * into non-blocking mode makes things annoying.
 */
VOID console_process_commands(Remote *remote)
{
	SOCKET fd = remote_get_fd(remote);
	struct timeval tv;
	fd_set fdread;
	LONG r;

	console_write_prompt();

	// Execute the scheduler in a loop
	while (1)
	{
		FD_ZERO(&fdread);
		FD_SET(fd, &fdread);

		tv.tv_sec  = 0;
		tv.tv_usec = 100;

		if ((r = select(fd + 1, &fdread, NULL, NULL, &tv)) > 0)
		{
			LONG bytes = 0;

			ioctlsocket(fd, FIONREAD, &bytes);

			if (bytes == 0)
			{
				console_write_output(
						"\n"
						"Connection reset by peer.\n");
				break;
			}

			command_process_remote(remote, NULL);
		}
		else if (r < 0)
			break;

		scheduler_run(remote, 0);
	}
}

VOID console_read_thread_func(Remote *remote)
{
	while (1)
		console_read_buffer(remote);
}

/*
 * Reads in data from the input device, potentially calling the 
 * command processing function if a complete command has been read.
 */
VOID console_read_buffer(Remote *remote)
{
	DWORD newInputBufferLength, stringLength, offset;
	Channel *interactiveChannel;
	PCHAR newInputBuffer;
	BOOL process = FALSE;
	CHAR buf[4096];
	PCHAR eoln, eolr;
	LONG bytesRead;

	// Ensure null termination
	buf[sizeof(buf) - 1] = 0;

	do
	{
		// Is there data available?
		if (WaitForSingleObject(GetStdHandle(STD_INPUT_HANDLE), INFINITE) 
				!= WAIT_OBJECT_0)
			break;

		// If a console escape character was sent and we're currently interactive,
		// break out of interactive mode
		if ((console_check_escape_sent()) &&
		    (console_get_interactive_channel()))
		{
			console_set_interactive_channel(remote, NULL);

			console_write_output(
					"\n"
					"\n"
					"Exiting interactive mode..\n");
			console_write_prompt();
		}

		// Read the command
		if ((!ReadConsole(GetStdHandle(STD_INPUT_HANDLE),
				buf, sizeof(buf) - 1, &bytesRead, NULL)) || (bytesRead <= 0))
			break;

		buf[bytesRead] = 0;

		// If an interactive channel is in use, write directly to it.
		if ((interactiveChannel = console_get_interactive_channel()))
		{
			channel_write(interactiveChannel, remote, NULL, 0, buf, 
					bytesRead, NULL);
			break;
		}

		if ((eoln = strchr(buf, '\n')))
		{
			*eoln = 0;

			process = TRUE;
		}

		// Remove end of line characters
		if ((eolr = strchr(buf, '\r')))
			*eolr = 0;

		// Calculate lengths
		stringLength         = strlen(buf);
		newInputBufferLength = inputBufferLength + stringLength;

		if (inputBuffer)
			newInputBuffer = (PCHAR)realloc(inputBuffer, 
					newInputBufferLength);
		else
			newInputBuffer = (PCHAR)malloc(++newInputBufferLength);

		// Allocation failure?
		if (!newInputBuffer)
			break;

		if ((offset = inputBufferLength))
			offset--;

		// Copy the string
		memcpy(newInputBuffer + offset, buf, stringLength);

		// Update the input buffer
		inputBuffer       = newInputBuffer;
		inputBufferLength = newInputBufferLength;

		// Process the full command line if it's completed
		if (process)
		{
			inputBuffer[inputBufferLength - 1] = 0;

			client_acquire_lock();
			console_process_command(remote);
			client_release_lock();

			free(inputBuffer);

			inputBuffer       = NULL;
			inputBufferLength = 0;

			console_write_prompt();
		}

	} while (0);
}

/*
 * Parse the local command into an argument vector
 *
 * TODO: 
 *
 *   - Add character unescaping (\x01)
 */
VOID console_process_command(Remote *remote)
{
	CHAR **argv = NULL, *current;
	ConsoleCommand *command = NULL;
	UINT argc, index;

	do
	{
		// Calculate the number of arguments
		for (current = inputBuffer, argc = 1;
			  current = strchr(current, ' ');
			  current++, argc++);

		current = inputBuffer;
		index   = 0;

		if (!(argv = (CHAR **)malloc(sizeof(PCHAR) * argc)))
			break;

		// Populate the argument vector
		while (1)
		{
			CHAR *space = NULL, *edquote = NULL;

			// If the first character of the current argument is a quote,
			// find the next quote.
			if (current[0] == '"')
			{
				if ((edquote = strchr(current + 1, '"')))
					*edquote = 0;
			}
			else	if ((space = strchr(current, ' ')))
				*space = 0;

			// If we're using quoting for this argument, skip one past current.
			argv[index++] = strdup(current + ((edquote) ? 1 : 0));
			current       = ((edquote) ? edquote : space) + 1;

			if (space)
				*space = ' ';
			else if (edquote)
				*edquote = '"';
			else
				break;
		}

		// Find the command
		for (index = 0;
			  consoleCommands[index].name;
			  index++)
		{
			if (!strcmp(consoleCommands[index].name, argv[0]))
			{
				command = &consoleCommands[index];
				break;
			}
		}

		// If the command was not found in the default command list, try looking
		// in the extended list
		if (!command)
		{
			for (command = extendedCommandsHead;
			     command;
			     command = command->next)
			{
				if (!strcmp(command->name, argv[0]))
					break;
			}
		}

		// The command was not found.
		if ((!command) || (!command->name))
			break;

		command->handler(remote, argc, argv);

	} while (0);

	// Cleanup argv
	if (argv)
	{
		for (index = 0; 
		     index < argc; 
		     index++)
			free(argv[index]);

		free(argv);
	}
}

/*
 * Dynamically registers a client command
 */
DWORD console_register_command(ConsoleCommand *command)
{
	ConsoleCommand *newConsoleCommand;

	if (!(newConsoleCommand = (ConsoleCommand *)malloc(sizeof(ConsoleCommand))))
		return ERROR_NOT_ENOUGH_MEMORY;

	memcpy(newConsoleCommand, command, sizeof(ConsoleCommand));

	if (extendedCommandsTail)
		extendedCommandsTail->next = newConsoleCommand;

	newConsoleCommand->prev = extendedCommandsTail;
	newConsoleCommand->next = NULL;
	extendedCommandsTail    = newConsoleCommand;
			
	if (!extendedCommandsHead)
		extendedCommandsHead = newConsoleCommand;

	return ERROR_SUCCESS;
}

/*
 * Dynamically deregisters a client command
 */
DWORD console_deregister_command(ConsoleCommand *command)
{
	ConsoleCommand *current, *prev;
	DWORD res = ERROR_NOT_FOUND;
	
	// Search the extension list for the command
	for (current = extendedCommandsHead, prev = NULL;
	     current;
	     prev = current, current = current->next)
	{
		if (strcmp(command->name, current->name))
			continue;

		if (prev)
			prev->next = current->next;
		else
			extendedCommandsHead = current->next;

		if (current->next)
			current->next->prev = prev;

		if (current == extendedCommandsTail)
			extendedCommandsTail = current->prev;

		// Deallocate it
		free(current);
		
		res = ERROR_SUCCESS;

		break;
	}

	return res;
}
