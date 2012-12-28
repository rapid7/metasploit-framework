/*
 * This server feature extension provides:
 *
 *
 */
#include "sample.h"

#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

DWORD request_sample_ping(Remote *remote, Packet *packet)
{
	
	LPCSTR ping_value;
	char * reply;
	DWORD dwResult    = ERROR_SUCCESS;	
	// Initialise response packet
	Packet * response = NULL;
	ping_value= packet_get_tlv_value_string(packet,TLV_TYPE_SAMPLE_PING);
	reply=(char *)malloc(1024); // UNSAFE!
	sprintf(reply,"You said: %s",ping_value);
	//printf("Enter\n");
	response = packet_create_response( packet );
	packet_add_tlv_string(response,TLV_TYPE_SAMPLE_PONG,reply);
	packet_transmit_response( dwResult, remote, response );
	return dwResult;
}

Command customCommands[] =
{
	{ "sample_ping",
	  { request_sample_ping,                                    { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
};

/*
 * Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	DWORD index;

	hMetSrv = remote->hMetSrv;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	DWORD index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_deregister(&customCommands[index]);

	return ERROR_SUCCESS;
}
