#include "precomp.h"

DWORD add_remove_route(Packet *request, BOOLEAN add);

/*
 * Returns zero or more routes to the requestor from the active routing table
 */
DWORD request_net_config_get_routes(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	PMIB_IPFORWARDTABLE table = NULL;
	DWORD tableSize = sizeof(MIB_IPFORWARDROW) * 96;
	DWORD index;

	do
	{
		// Allocate storage for the routing table
		if (!(table = (PMIB_IPFORWARDTABLE)malloc(tableSize)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the routing table
		if (GetIpForwardTable(table, &tableSize, TRUE) != NO_ERROR)
		{
			result = GetLastError();
			break;
		}

		// Enumerate it
		for (index = 0;
		     index < table->dwNumEntries;
		     index++)
		{
			Tlv route[3];

			route[0].header.type   = TLV_TYPE_SUBNET;
			route[0].header.length = sizeof(DWORD);
			route[0].buffer        = (PUCHAR)&table->table[index].dwForwardDest;
			route[1].header.type   = TLV_TYPE_NETMASK;
			route[1].header.length = sizeof(DWORD);
			route[1].buffer        = (PUCHAR)&table->table[index].dwForwardMask;
			route[2].header.type   = TLV_TYPE_GATEWAY;
			route[2].header.length = sizeof(DWORD);
			route[2].buffer        = (PUCHAR)&table->table[index].dwForwardNextHop;

			packet_add_tlv_group(response, TLV_TYPE_NETWORK_ROUTE,
					route, 3);
		}

	} while (0);

	if (table)
		free(table);

	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Adds a route to the routing table
 */
DWORD request_net_config_add_route(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;

	result = add_remove_route(packet, TRUE);

	// Transmit the response packet
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Removes a route from the routing table
 */
DWORD request_net_config_remove_route(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result;

	result = add_remove_route(packet, FALSE);

	// Transmit the response packet
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Adds or removes a route from the supplied request
 */
DWORD add_remove_route(Packet *packet, BOOLEAN add)
{
	MIB_IPFORWARDROW route;
	LPCSTR subnet;
	LPCSTR netmask;
	LPCSTR gateway;

	subnet  = packet_get_tlv_value_string(packet, TLV_TYPE_SUBNET_STRING);
	netmask = packet_get_tlv_value_string(packet, TLV_TYPE_NETMASK_STRING);
	gateway = packet_get_tlv_value_string(packet, TLV_TYPE_GATEWAY_STRING);

	memset(&route, 0, sizeof(route));

	route.dwForwardDest    = inet_addr(subnet);
	route.dwForwardMask    = inet_addr(netmask);
	route.dwForwardNextHop = inet_addr(gateway);

	if (add)
		return CreateIpForwardEntry(&route);
	else
		return DeleteIpForwardEntry(&route);
}
