#include "precomp.h"

DWORD add_remove_route(Packet *request, BOOLEAN add);

/*
 * Returns zero or more routes to the requestor from the active routing table
 */
DWORD request_net_config_get_routes(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	DWORD index;

#ifdef _WIN32
	PMIB_IPFORWARDTABLE table = NULL;
	DWORD tableSize = sizeof(MIB_IPFORWARDROW) * 96;

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

#else 
	struct ipv4_routing_table *table = NULL;

	dprintf("[%s] getting routing table", __FUNCTION__);
	result = netlink_get_ipv4_routing_table(&table);
	dprintf("[%s] result = %d, table = %p", __FUNCTION__, result, table);

	for(index = 0; index < table->entries; index++) {
		Tlv route[3];

		route[0].header.type	= TLV_TYPE_SUBNET;
		route[0].header.length 	= sizeof(DWORD);
		route[0].buffer 	= (PUCHAR)&table->routes[index].dest;
	
		route[1].header.type	= TLV_TYPE_NETMASK;
		route[1].header.length	= sizeof(DWORD);
		route[1].buffer		= (PUCHAR)&table->routes[index].netmask;
		
		route[2].header.type	= TLV_TYPE_GATEWAY;
		route[2].header.length	= sizeof(DWORD);
		route[2].buffer		= (PUCHAR)&table->routes[index].nexthop;
		
		packet_add_tlv_group(response, TLV_TYPE_NETWORK_ROUTE, route, 3);
	}

#endif

	if(table) 
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
#ifdef _WIN32
	MIB_IPFORWARDROW route;
	DWORD (WINAPI *LocalGetBestInterface)(IPAddr, LPDWORD) = NULL;
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
	route.dwForwardType    = 4; // Assume next hop.
	route.dwForwardProto   = 3;
	route.dwForwardAge     = -1;

	if ((LocalGetBestInterface = (DWORD (WINAPI *)(IPAddr, LPDWORD))GetProcAddress(
			GetModuleHandle("iphlpapi"),
			"GetBestInterface")))
	{
		DWORD result = LocalGetBestInterface(route.dwForwardDest, 
				&route.dwForwardIfIndex);

		if (result != ERROR_SUCCESS)
			return result;
	}
	// I'm lazy.  Need manual lookup of ifindex based on gateway for NT.
	else
		return ERROR_NOT_SUPPORTED;

	if (add)
		return CreateIpForwardEntry(&route);
	else
		return DeleteIpForwardEntry(&route);

#else
	return ERROR_NOT_SUPPORTED;
#endif

}
