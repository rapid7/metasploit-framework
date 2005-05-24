#include "metcli.h"

extern ConsoleCommand consoleCommands[];
extern ConsoleCommand *extendedCommandsHead;

/*****************
 * Command: help *
 *****************/

VOID cmd_help_output_command(ConsoleCommand *command)
{
	if (command->separator)
		console_write_output(
				"\n%13s   %s\n"
				" ------------   ---------------\n",
				command->name, command->help);
	else
		console_write_output("%13s   %s\n", command->name,
				command->help);
}

/*
 * Print the help banner
 */
DWORD cmd_help(Remote *remote, UINT argc, CHAR **argv)
{
	ConsoleCommand *current;
	DWORD index;

	for (index = 0;
	     consoleCommands[index].name;
	     index++)
		cmd_help_output_command(&consoleCommands[index]);

	for (current = extendedCommandsHead;
	     current;
	     current = current->next)
		cmd_help_output_command(current);

	return ERROR_SUCCESS;
}

/*****************
 * Command: open *
 *****************/

/*
 * Opens a logical channel with the remote endpoint that is not tied to
 * a stream
 */
DWORD cmd_open(Remote *remote, UINT argc, CHAR **argv)
{
	DWORD res;

	if ((res = channel_open(remote, NULL, 0, NULL)) == ERROR_SUCCESS)
		console_write_output(
				OUTBOUND_PREFIX " CHANNEL: Requesting a new channel...\n");
	else
		console_write_output(
				"Error: channel_open failed, result %lu.\n", res);

	return res;
}

/*****************
 * Command: read *
 *****************/

/*
 * Channel completion routine for reading from a channel
 */
DWORD cmd_read_channel_complete(Remote *remote, Channel *channel,
		LPVOID context, DWORD result, PUCHAR buffer, ULONG bytesRead)
{
	if (result == ERROR_SUCCESS && bytesRead > 0)
	{
		PCHAR tmp = (PCHAR)malloc(bytesRead + 1);

		if (tmp)
		{
			// Copy the buffer into tmp and null terminate it
			memcpy(tmp, buffer, bytesRead);
			tmp[bytesRead] = 0;

			console_write_output(
					"\n"
					INBOUND_PREFIX " CHANNEL: read %lu bytes from channel %lu:\n"
					"%s"
					"\n",
					bytesRead, channel_get_id(channel), tmp);

			free(tmp);
		}
		else
			console_write_output(
					"\n"
					INBOUND_PREFIX " CHANNEL: read %lu bytes, local allocation failed.\n",
					bytesRead);
	}
	else if (result != ERROR_SUCCESS)
		console_write_output(
				"\n"
				INBOUND_PREFIX " CHANNEL: cmd_read failed, result %lu.\n", result);

	console_write_prompt();

	return ERROR_SUCCESS;
}

/*
 * Reads in data from the remote endpoint of a channel
 */
DWORD cmd_read(Remote *remote, UINT argc, CHAR **argv)
{
	ChannelCompletionRoutine complete;
	DWORD channelId = 0, length = 4096;
	DWORD res = ERROR_SUCCESS;
	Channel *channel;

	do
	{
		// Check to see if the supplied channel identifier is valid
		if (argc == 1)
		{
			console_write_output("Usage: read channel_id [length]\n");
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		channelId = strtoul(argv[1], NULL, 10);

		// If a length was provided, use it.
		if (argc > 2)
			length = strtoul(argv[2], NULL, 10);

		if (!(channel = channel_find_by_id(channelId)))
		{
			console_write_output("Error: Could not locate channel %lu.\n", 
					channelId);
			break;
		}

		// Initialize the completion routine
		memset(&complete, 0, sizeof(complete));

		complete.routine.read = cmd_read_channel_complete;

		// Read the data in.
		if ((res = channel_read(channel, remote, NULL, 0, length, 
				&complete)) 
				== ERROR_SUCCESS)
			console_write_output(
					OUTBOUND_PREFIX " CHANNEL: Requesting %lu bytes from channel %lu...\n",
					length, channelId);
		else
			console_write_output("Error: channel_read failed, result %lu.\n", res);

	} while (0);

	return ERROR_SUCCESS;
}

/******************
 * Command: write *
 ******************/

/*
 * Completion routine for a previous write
 */
DWORD cmd_write_channel_complete(Remote *remote, Channel *channel,
		LPVOID context, DWORD result, ULONG bytesWritten)
{
	if (result == ERROR_SUCCESS)
		console_write_output(
				"\n"
				INBOUND_PREFIX " CHANNEL: Wrote %lu bytes to channel %lu.\n",
				bytesWritten, channel_get_id(channel));
	else
		console_write_output(
				"\n"
				INBOUND_PREFIX " CHANNEL: write failed, result %lu.\n",
				result);

	console_write_prompt();

	return ERROR_SUCCESS;
}

/*
 * Writes the supplied text to the remote end of the channel
 */
DWORD cmd_write(Remote *remote, UINT argc, CHAR **argv)
{
	ChannelCompletionRoutine complete;
	DWORD channelId = 0;
	DWORD res = ERROR_SUCCESS;
	Channel *channel;
	DWORD length = 0;
	LONG bytesRead;
	PCHAR buffer = NULL;
	CHAR chunk[2048];

	chunk[sizeof(chunk) - 1] = 0;

	do
	{
		// Check to see if the supplied channel identifier is valid
		if (argc < 2)
		{
			console_write_output("Usage: write channel_id\n");
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		channelId = strtoul(argv[1], NULL, 10);

		if (!(channel = channel_find_by_id(channelId)))
		{
			console_write_output("Error: Could not locate channel %lu.\n", 
					channelId);
			break;
		}

		console_write_output("Enter text, terminate with single-line '.':\n");

		/*
		 * XXX: needs to not use stdin for non-cmd input
		 */
		while (fgets(chunk, sizeof(chunk) - 1, stdin))
		{
			PCHAR newBuffer;

			if (chunk[0] == '.')
				break;

			bytesRead = strlen(chunk);

			if (!buffer)
				newBuffer = (PCHAR)malloc(bytesRead);
			else
				newBuffer = (PCHAR)realloc(buffer, length + bytesRead);

			if (!newBuffer)
			{
				if (buffer)
					free(buffer);

				buffer = NULL;

				break;
			}

			memcpy(newBuffer + length, chunk, bytesRead);

			buffer  = newBuffer;
			length += bytesRead;
		}

		if (!buffer)
		{
			console_write_output(
					"Error: No text was provided.\n");
			break;
		}

		// Initialize the completion routine
		memset(&complete, 0, sizeof(complete));

		complete.routine.write = cmd_write_channel_complete;

		// Read the data in.
		if ((res = channel_write(channel, remote, NULL, 0, buffer, 
				length, &complete)) 
				== ERROR_SUCCESS)
			console_write_output(
					OUTBOUND_PREFIX " CHANNEL: Writing %lu bytes to channel %lu...\n",
					length, channelId);
		else
			console_write_output("Error: channel_write failed, result %lu.\n", res);

		free(buffer);

	} while (0);

	return ERROR_SUCCESS;
}

/******************
 * Command: close *
 ******************/

/*
 * Closes a channel that was allocated with the remote endpoint
 */
DWORD cmd_close(Remote *remote, UINT argc, CHAR **argv)
{
	DWORD res = ERROR_SUCCESS;
	DWORD channelId;
	Channel *channel;

	do
	{
		if (argc == 1)
		{
			console_write_output(
					"Usage: close channel_id\n");
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		channelId = strtoul(argv[1], NULL, 10);

		// Find the channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			console_write_output("Error: Could not locate channel id %lu.\n", 
					channelId);

			res = ERROR_NOT_FOUND;
			break;
		}

		if ((res = channel_close(channel, remote, NULL, 0, NULL)) 
				== ERROR_SUCCESS)
			console_write_output(
					OUTBOUND_PREFIX " CHANNEL: Closing channel %lu...\n", channelId);
		else
			console_write_output("Error: channel_close failed, result %lu.\n", 
					res);

	} while (0);

	return res;
}

/*********************
 * Command: interact *
 *********************/

/*
 * Completion routine for when interact responds
 */
DWORD cmd_interact_complete(Remote *remote, Channel *channel,
		LPVOID context, DWORD result)
{
	if (result == ERROR_SUCCESS)
	{
		console_write_output(
				"\n"
				INBOUND_PREFIX " CHANNEL: Started interactive with channel %lu..\n\n",
				channel_get_id(channel));
		
		console_set_interactive_channel(remote, channel);
	}
	else
	{
		console_write_output(
				"\n"
				INBOUND_PREFIX " CHANNEL: Failed to interact with channel %lu, result %lu.\n",
				channel_get_id(channel));

		console_write_prompt();
	}
	
	return ERROR_SUCCESS;
}

/*
 * Switches to interactive mode with a a provided channel
 */
DWORD cmd_interact(Remote *remote, UINT argc, CHAR **argv)
{
	ChannelCompletionRoutine complete;
	DWORD res = ERROR_SUCCESS;
	Channel *channel;

	do
	{
		if (argc == 1)
		{
			console_write_output(
					"Usage: interact channel_id\n");
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		// Try to find the channel context from the supplied identifier
		if (!(channel = channel_find_by_id(strtoul(argv[1], NULL, 10))))
		{
			console_write_output(
					"Error: The channel identifier %s could not be found.\n",
					argv[1]);
			res = ERROR_NOT_FOUND;
			break;
		}

		console_write_output(
				OUTBOUND_PREFIX " CHANNEL: Switching to interactive console on %lu.\n", 
				channel_get_id(channel));

		// Initialize the completion routine
		memset(&complete, 0, sizeof(complete));

		complete.routine.interact = cmd_interact_complete;

		// Interact with the channel
		res = channel_interact(channel, remote, NULL, 0, TRUE,
				&complete);

	} while (0);

	return res;
}

/*****************
 * Command: exit *
 *****************/

/*
 * Exit the client
 */
DWORD cmd_exit(Remote *remote, UINT argc, CHAR **argv)
{
	exit(0);
	
	return ERROR_SUCCESS;
}

/********************
 * Command: loadlib *
 ********************/

/*
 * Load library completion routine
 */
DWORD cmd_loadlib_complete(Remote *remote, Packet *packet, LPVOID context,
		LPCSTR method, DWORD res)
{
	return console_generic_response_output(remote, packet, "PROCESS", "loadlib");
}

/*
 * Loads a library into the context of the remote process
 */
DWORD cmd_loadlib(Remote *remote, UINT argc, CHAR **argv)
{
	PCHAR libraryPath = NULL, targetPath = NULL;
	PacketRequestCompletion complete;
	Packet *request = NULL;
	BOOL printBanner = FALSE;
	DWORD res = ERROR_SUCCESS;
	ArgumentContext arg;
	DWORD flags = 0;

	// Zero the argument context
	memset(&arg, 0, sizeof(arg));

	do
	{
		// No arguments?
		if (argc == 1)
		{
			printBanner = TRUE;
			break;
		}
	
		// Default to being a local (to the remote machine) library
		flags |= LOAD_LIBRARY_FLAG_LOCAL;

		// Parse the supplied arguments
		while (args_parse(argc, argv, "f:t:lde", &arg) == ERROR_SUCCESS)
		{
			switch (arg.toggle)
			{
				case 'f':
					libraryPath = arg.argument;
					break;
				case 't':
					targetPath = arg.argument;
					break;
				case 'l':
					// Unset the local library flag
					flags &= ~(LOAD_LIBRARY_FLAG_LOCAL);
					break;
				case 'd':
					flags |= LOAD_LIBRARY_FLAG_ON_DISK;
					break;
				case 'e':
					flags |= LOAD_LIBRARY_FLAG_EXTENSION;
					break;
				default:
					break;
			}
		}

		if (!targetPath)
			targetPath = libraryPath;

		// Make sure that a library was supplied
		if (!libraryPath)
		{
			console_write_output(
					"Error: No library path was specified.\n");
			break;
		}

		// Allocate the request packet
		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST,
				"core_loadlib")))
		{
			console_write_output(
					"Error: Packet allocation failure.\n");
			break;
		}

		// If the library is not local to the remote machine, parse the local
		// copy into a data buffer to be transmitted to the remote host
		if (!(flags & LOAD_LIBRARY_FLAG_LOCAL))
		{
			PUCHAR buffer;
			ULONG length;

			// Store the contents of the specified file in a buffer
			if ((res = buffer_from_file(libraryPath, &buffer, &length)) 
					!= ERROR_SUCCESS)
			{
				console_write_output(
						"Error: The local file could not be parsed, result %lu.\n",
						res);
				break;
			}

			// Add the file's contents as a data tlv
			packet_add_tlv_raw(request, TLV_TYPE_DATA, buffer, 
					length);

			console_write_output(
					OUTBOUND_PREFIX " PROCESS: Uploading local library '%s', %lu bytes.\n",
					libraryPath, length);

			free(buffer);
		}

		// Add the library path name & flags
		packet_add_tlv_string(request, TLV_TYPE_LIBRARY_PATH,
				libraryPath);
		packet_add_tlv_uint(request, TLV_TYPE_FLAGS,
				flags);

		if (targetPath)
			packet_add_tlv_string(request, TLV_TYPE_TARGET_PATH,
					targetPath);

		console_write_output(
				OUTBOUND_PREFIX " PROCESS: Loading library from '%s' on remote machine.\n", 
				targetPath ? targetPath : libraryPath);
		
		// Initialize the completion routine
		memset(&complete, 0, sizeof(complete));

		complete.routine = cmd_loadlib_complete;
		
		// Transmit the request
		res = packet_transmit(remote, request, &complete);

	} while (0);

	if (printBanner)
	{
		console_write_output(
				"Usage: loadlib -f library [ -t target ] [ -lde ]\n\n"
				"  -f <file>  The path to the library to load, whether local or remote.\n"
				"  -t <targ>  The target file on the remote machine in which to store the library when uploading.\n"
				"  -l         The library is local to the client machine, upload it to the remote machine.\n"
				"  -d         When used with -l, this parameter indicates that the library should be saved to disk.\n"
				"  -e         The library being loaded is a feature extension module, call its Init routine on load.\n");
	}

	return res;
}

/****************
 * Command: use *
 ****************/

/*
 * Use a feature module implementation, installing it both locally and remotely
 */
DWORD cmd_use(Remote *remote, UINT argc, CHAR **argv)
{
	LPCSTR module = NULL, path = NULL;
	PCHAR currentModule = NULL, comma;
	BOOL printBanner = FALSE;
	DWORD res = ERROR_SUCCESS;
	CHAR clientLibraryPath[1024];
	CHAR serverLibraryPath[1024];
	BOOL diskOnly = FALSE;
	ArgumentContext arg;
	CHAR *loadlibArgv[6];
	DWORD loadlibArgc = 0;

	clientLibraryPath[sizeof(clientLibraryPath) - 1] = 0;
	serverLibraryPath[sizeof(serverLibraryPath) - 1] = 0;

	memset(&arg, 0, sizeof(arg));

	do
	{
		// No arguments?
		if (argc == 1)
		{
			printBanner = TRUE;
			break;
		}

		// Parse the supplied arguments
		while (args_parse(argc, argv, "m:p:d", &arg) == ERROR_SUCCESS)
		{
			switch (arg.toggle)
			{
				case 'm':
					module = arg.argument;
					break;
				case 'p':
					path = arg.argument;
					break;
				case 'd':
					diskOnly = TRUE;
					break;
				default:
					break;
			}
		}

		// No module?
		if (!module)
		{
			printBanner = TRUE;
			break;
		}

		currentModule = (PCHAR)module;

		// Enumerate through the comma delimited module list
		while (currentModule)
		{
			comma = strchr(currentModule, ',');

			if (comma)
				*comma = 0;

			// Populate the client and server path buffers
			_snprintf(clientLibraryPath, sizeof(clientLibraryPath) - 1,
					"%s%sext_client_%s.dll", 
					(path) ? path : "",
					(path) ? "\\" : "",
					currentModule);
			_snprintf(serverLibraryPath, sizeof(clientLibraryPath) - 1,
					"%s%sext_server_%s.dll", 
					(path) ? path : "",
					(path) ? "\\" : "",
					currentModule);

			// Try to load the client library
			if ((res = module_load_client(remote, currentModule, clientLibraryPath))
					!= ERROR_SUCCESS)
				break;

			console_write_output("Successfully loaded '%s' on the client.\n", currentModule);

			loadlibArgc = 0;

			loadlibArgv[loadlibArgc++] = "loadlib";

			// Now load the library on the remote machine
			if (diskOnly)
			{
				// loadlib -f server_mod_path -e
				loadlibArgv[loadlibArgc++] = "-f";
				loadlibArgv[loadlibArgc++] = serverLibraryPath;
				loadlibArgv[loadlibArgc++] = "-e";
			}
			else
			{
				// loadlib -f server_mod_path -l -e
				loadlibArgv[loadlibArgc++] = "-f";
				loadlibArgv[loadlibArgc++] = serverLibraryPath;
				loadlibArgv[loadlibArgc++] = "-l";
				loadlibArgv[loadlibArgc++] = "-e";
			}

			// Call the load library command
			res = cmd_loadlib(remote, loadlibArgc, loadlibArgv);

			if (comma)
			{
				*comma        = ',';
				currentModule = comma + 1;
			}
			else
				currentModule = NULL;
		}

	} while (0);

	if (printBanner)
	{
		console_write_output(
				"Usage: use -m module1,module2,module3 [ -p path ] [ -d ]\n\n"
				"  -m <mod>   The names of one or more module(s) to load (e.g. 'net').\n"
				"  -p <path>  The path to load the module(s) from locally.\n"
				"  -d         Load the library from disk, do not upload.\n");
	}

	return res;
}
