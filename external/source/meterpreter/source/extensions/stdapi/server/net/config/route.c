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
	DWORD metric_bigendian;

#ifdef _WIN32
	PMIB_IPFORWARDTABLE table_ipv4 = NULL;
	PMIB_IPFORWARDTABLE table_ipv6 = NULL;
	DWORD tableSize = sizeof(MIB_IPFORWARDROW) * 96;
	unsigned char int_name[20];

	do
	{
		// Allocate storage for the routing table
		if (!(table_ipv4 = (PMIB_IPFORWARDTABLE)malloc(tableSize)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the routing table
		if (GetIpForwardTable(table_ipv4, &tableSize, TRUE) != NO_ERROR)
		{
			result = GetLastError();
			break;
		}

		// Enumerate it
		for (index = 0;
		     index < table_ipv4->dwNumEntries;
		     index++)
		{
			Tlv route[5];
			memset(int_name, 0, 20);
			
			route[0].header.type   = TLV_TYPE_SUBNET;
			route[0].header.length = sizeof(DWORD);
			route[0].buffer        = (PUCHAR)&table_ipv4->table[index].dwForwardDest;
			route[1].header.type   = TLV_TYPE_NETMASK;
			route[1].header.length = sizeof(DWORD);
			route[1].buffer        = (PUCHAR)&table_ipv4->table[index].dwForwardMask;
			route[2].header.type   = TLV_TYPE_GATEWAY;
			route[2].header.length = sizeof(DWORD);
			route[2].buffer        = (PUCHAR)&table_ipv4->table[index].dwForwardNextHop;

			// we just get the interface index, not the name, because names can be __long__
            _itoa(table_ipv4->table[index].dwForwardIfIndex, int_name, 10);
    		route[3].header.type   = TLV_TYPE_STRING;
			route[3].header.length = strlen(int_name)+1;
			route[3].buffer        = (PUCHAR)int_name;

			metric_bigendian = htonl(table_ipv4->table[index].dwForwardMetric1);
			route[4].header.type   = TLV_TYPE_ROUTE_METRIC;
			route[4].header.length = sizeof(DWORD);
			route[4].buffer        = (PUCHAR)&metric_bigendian;

			packet_add_tlv_group(response, TLV_TYPE_NETWORK_ROUTE,
					route, 5);
		}

	} while (0);

#else 
	struct ipv4_routing_table *table_ipv4 = NULL;
	struct ipv6_routing_table *table_ipv6 = NULL;

	dprintf("getting routing table");
	result = netlink_get_routing_table(&table_ipv4, &table_ipv6);
	dprintf("result = %d, table_ipv4 = %p, table_ipv6=%p", result, table_ipv4,table_ipv6);

	for(index = 0; index < table_ipv4->entries; index++) {
		Tlv route[5];

		route[0].header.type	= TLV_TYPE_SUBNET;
		route[0].header.length 	= sizeof(DWORD);
		route[0].buffer 		= (PUCHAR)&table_ipv4->routes[index].dest;
	
		route[1].header.type	= TLV_TYPE_NETMASK;
		route[1].header.length	= sizeof(DWORD);
		route[1].buffer			= (PUCHAR)&table_ipv4->routes[index].netmask;
		
		route[2].header.type	= TLV_TYPE_GATEWAY;
		route[2].header.length	= sizeof(DWORD);
		route[2].buffer			= (PUCHAR)&table_ipv4->routes[index].nexthop;

		route[3].header.type   = TLV_TYPE_STRING;
		route[3].header.length = strlen((PUCHAR)table_ipv4->routes[index].interface)+1;
		route[3].buffer        = (PUCHAR)table_ipv4->routes[index].interface;

		metric_bigendian 	   = htonl(table_ipv4->routes[index].metric);
		route[4].header.type   = TLV_TYPE_ROUTE_METRIC;
		route[4].header.length = sizeof(DWORD);
		route[4].buffer        = (PUCHAR)&metric_bigendian;
		
		packet_add_tlv_group(response, TLV_TYPE_NETWORK_ROUTE, route, 5);
	}
	dprintf("sent %d IPv4 routes", table_ipv4->entries);
	// IPv6 routing table
	for(index = 0; index < table_ipv6->entries; index++) {
		Tlv route6[5];

		route6[0].header.type	= TLV_TYPE_SUBNET;
		route6[0].header.length = sizeof(__u128);
		route6[0].buffer 		= (PUCHAR)&table_ipv6->routes[index].dest6;
	
		route6[1].header.type	= TLV_TYPE_NETMASK;
		route6[1].header.length	= sizeof(__u128);
		route6[1].buffer		= (PUCHAR)&table_ipv6->routes[index].netmask6;
		
		route6[2].header.type	= TLV_TYPE_GATEWAY;
		route6[2].header.length	= sizeof(__u128);
		route6[2].buffer		= (PUCHAR)&table_ipv6->routes[index].nexthop6;

		route6[3].header.type   = TLV_TYPE_STRING;
		route6[3].header.length = strlen((PUCHAR)table_ipv6->routes[index].interface)+1;
		route6[3].buffer        = (PUCHAR)table_ipv6->routes[index].interface;

		metric_bigendian 	    = htonl(table_ipv6->routes[index].metric);
		route6[4].header.type   = TLV_TYPE_ROUTE_METRIC;
		route6[4].header.length = sizeof(DWORD);
		route6[4].buffer        = (PUCHAR)&metric_bigendian;
		
		packet_add_tlv_group(response, TLV_TYPE_NETWORK_ROUTE, route6, 5);
	}
	dprintf("sent %d IPv6 routes", table_ipv6->entries);

#endif

	if(table_ipv4) 
		free(table_ipv4);
	if(table_ipv6) 
		free(table_ipv6);

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
