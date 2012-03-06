#include "precomp.h"
#include <ws2ipdef.h>

/*
 * Returns zero or more local interfaces to the requestor
 */
DWORD request_net_config_get_interfaces(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	DWORD entryCount;

#ifdef _WIN32
	Tlv entries[6];
	PMIB_IPADDRTABLE table = NULL;
	DWORD tableSize = sizeof(MIB_IPADDRROW) * 33;
	DWORD index;
	DWORD mtu_bigendian;
	DWORD interface_index_bigendian;
	MIB_IFROW iface;

	ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_DNS_SERVER;
	LPSOCKADDR sockaddr;

	ULONG family = AF_UNSPEC;
	IP_ADAPTER_ADDRESSES *pAdapters = NULL;
	IP_ADAPTER_ADDRESSES *pCurr = NULL;
	ULONG outBufLen = 0;

	IP_ADAPTER_UNICAST_ADDRESS_LH *pAddr;
	LPSOCKADDR foo;

	// Call once with a length of 0 to get how much we need to allocate
	GetAdaptersAddresses(family, flags, NULL, pAdapters, &outBufLen);

	do
	{
		// Allocate memory for reading addresses into
		if (!(pAdapters = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the IP address table
		if (GetAdaptersAddresses(family, flags, NULL, pAdapters, &outBufLen))
		{
			result = GetLastError();
			break;
		}

		// Enumerate the entries
		for (pCurr = pAdapters; pCurr; pCurr = pCurr->Next)
		{
			entryCount = 0;

			interface_index_bigendian = htonl(pCurr->IfIndex);
			entries[entryCount].header.length = sizeof(DWORD);
			entries[entryCount].header.type   = TLV_TYPE_INTERFACE_INDEX;
			entries[entryCount].buffer        = (PUCHAR)&interface_index_bigendian;
			entryCount++;

			for (pAddr = (void*)pCurr->FirstUnicastAddress; pAddr; pAddr = (void*)pAddr->Next)
			{
				foo = pAddr->Address.lpSockaddr;
				if (foo->sa_family == AF_INET) {
					entries[entryCount].header.length = 4;
					entries[entryCount].header.type   = TLV_TYPE_IP;
					entries[entryCount].buffer        = (PUCHAR)&(((struct sockaddr_in *)foo)->sin_addr);
				} else {
					entries[entryCount].header.length = 16;
					entries[entryCount].header.type   = TLV_TYPE_IP;
					entries[entryCount].buffer        = (PUCHAR)&(((struct sockaddr_in6 *)foo)->sin6_addr);
				}
				entryCount++;

#if 0
				entries[entryCount].header.length = sizeof(DWORD);
				entries[entryCount].header.type   = TLV_TYPE_NETMASK;
				entries[entryCount].buffer        = (PUCHAR)&;
				entryCount++;
#endif
			}

#if 0
			// If interface information can get gotten, use it.
			if (GetIfEntry(&iface) == NO_ERROR)
			{
				entries[entryCount].header.length = iface.dwPhysAddrLen;
				entries[entryCount].header.type   = TLV_TYPE_MAC_ADDR;
				entries[entryCount].buffer        = (PUCHAR)iface.bPhysAddr;
				entryCount++;

				mtu_bigendian = htonl(iface.dwMtu);
				entries[entryCount].header.length = sizeof(DWORD);
				entries[entryCount].header.type   = TLV_TYPE_INTERFACE_MTU;
				entries[entryCount].buffer        = (PUCHAR)&mtu_bigendian;
				entryCount++;

				if (iface.bDescr)
				{
					entries[entryCount].header.length = iface.dwDescrLen + 1;
					entries[entryCount].header.type   = TLV_TYPE_MAC_NAME;
					entries[entryCount].buffer        = (PUCHAR)iface.bDescr;
					entryCount++;
				}
			}
#endif

			// Add the interface group
			packet_add_tlv_group(response, TLV_TYPE_NETWORK_INTERFACE,
					entries, entryCount);
		}

	} while (0);

	if (table)
		free(table);

#else
	struct ifaces_list *ifaces = NULL;
	int i;
	int if_error;
	uint32_t interface_index_bigendian, mtu_bigendian;
	// wild guess, should probably malloc
	Tlv entries[39];

	dprintf("Grabbing interfaces");
	if_error = netlink_get_interfaces(&ifaces);
	dprintf("Got 'em");

	if (if_error) {
		result = if_error;
	} else {
		for (i = 0; i < ifaces->entries; i++) {
			int tlv_cnt = 0;
			int j = 0;
			dprintf("Building TLV for iface %d", i);

			entries[tlv_cnt].header.length = strlen(ifaces->ifaces[i].name)+1;
			entries[tlv_cnt].header.type   = TLV_TYPE_MAC_NAME;
			entries[tlv_cnt].buffer        = (PUCHAR)ifaces->ifaces[i].name;
			tlv_cnt++;

			entries[tlv_cnt].header.length = 6;
			entries[tlv_cnt].header.type   = TLV_TYPE_MAC_ADDR;
			entries[tlv_cnt].buffer        = (PUCHAR)ifaces->ifaces[i].hwaddr;
			tlv_cnt++;

			for (j = 0; j < ifaces->ifaces[i].addr_count; j++) {
				if (ifaces->ifaces[i].addr_list[j].family == AF_INET) {
					dprintf("ip addr for %s", ifaces->ifaces[i].name);
					entries[tlv_cnt].header.length = sizeof(__u32);
					entries[tlv_cnt].header.type   = TLV_TYPE_IP;
					entries[tlv_cnt].buffer        = (PUCHAR)&ifaces->ifaces[i].addr_list[j].ip.addr;
					tlv_cnt++;

					//dprintf("netmask for %s", ifaces->ifaces[i].name);
					entries[tlv_cnt].header.length = sizeof(__u32);
					entries[tlv_cnt].header.type   = TLV_TYPE_NETMASK;
					entries[tlv_cnt].buffer        = (PUCHAR)&ifaces->ifaces[i].addr_list[j].nm.netmask;
					tlv_cnt++;
				} else {
					dprintf("-- ip six addr for %s", ifaces->ifaces[i].name);
					entries[tlv_cnt].header.length = sizeof(__u128);
					entries[tlv_cnt].header.type   = TLV_TYPE_IP;
					entries[tlv_cnt].buffer        = (PUCHAR)&ifaces->ifaces[i].addr_list[j].ip.addr6;
					tlv_cnt++;

					//dprintf("netmask6 for %s", ifaces->ifaces[i].name);
					entries[tlv_cnt].header.length = sizeof(__u128);
					entries[tlv_cnt].header.type   = TLV_TYPE_NETMASK;
					entries[tlv_cnt].buffer        = (PUCHAR)&ifaces->ifaces[i].addr_list[j].nm.netmask6;
					tlv_cnt++;
				}
			}

			mtu_bigendian            = htonl(ifaces->ifaces[i].mtu);
			entries[tlv_cnt].header.length = sizeof(uint32_t);
			entries[tlv_cnt].header.type   = TLV_TYPE_INTERFACE_MTU;
			entries[tlv_cnt].buffer        = (PUCHAR)&mtu_bigendian;
			tlv_cnt++;

			entries[tlv_cnt].header.length = strlen(ifaces->ifaces[i].flags)+1;
			entries[tlv_cnt].header.type   = TLV_TYPE_INTERFACE_FLAGS;
			entries[tlv_cnt].buffer        = (PUCHAR)ifaces->ifaces[i].flags;
			tlv_cnt++;

			interface_index_bigendian = htonl(ifaces->ifaces[i].index);
			entries[tlv_cnt].header.length = sizeof(uint32_t);
			entries[tlv_cnt].header.type   = TLV_TYPE_INTERFACE_INDEX;
			entries[tlv_cnt].buffer        = (PUCHAR)&interface_index_bigendian;
			tlv_cnt++;

			dprintf("Adding TLV to group");
			packet_add_tlv_group(response, TLV_TYPE_NETWORK_INTERFACE, entries, tlv_cnt);
			dprintf("done Adding TLV to group");
		}
	}

	if (ifaces)
		free(ifaces);
#endif

	// Transmit the response if valid
	packet_transmit_response(result, remote, response);

	return result;
}




