#include "precomp.h"

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

	do
	{
		// Allocate memory for reading addresses into
		if (!(table = (PMIB_IPADDRTABLE)malloc(tableSize)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the IP address table
		if (GetIpAddrTable(table, &tableSize, TRUE) != NO_ERROR)
		{
			result = GetLastError();
			break;
		}

		// Enumerate the entries
		for (index = 0;
		     index < table->dwNumEntries;
		     index++)
		{
			entryCount = 0;

			interface_index_bigendian = htonl(table->table[index].dwIndex);
			entries[entryCount].header.length = sizeof(DWORD);
			entries[entryCount].header.type   = TLV_TYPE_INTERFACE_INDEX;
			entries[entryCount].buffer        = (PUCHAR)&interface_index_bigendian;
			entryCount++;

			entries[entryCount].header.length = sizeof(DWORD);
			entries[entryCount].header.type   = TLV_TYPE_IP;
			entries[entryCount].buffer        = (PUCHAR)&table->table[index].dwAddr;
			entryCount++;

			entries[entryCount].header.length = sizeof(DWORD);
			entries[entryCount].header.type   = TLV_TYPE_NETMASK;
			entries[entryCount].buffer        = (PUCHAR)&table->table[index].dwMask;
			entryCount++;

			iface.dwIndex = table->table[index].dwIndex;

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
					entries[tlv_cnt].header.type   = TLV_TYPE_IP6;
					entries[tlv_cnt].buffer        = (PUCHAR)&ifaces->ifaces[i].addr_list[j].ip.addr6;
					tlv_cnt++;

					//dprintf("netmask6 for %s", ifaces->ifaces[i].name);
					entries[tlv_cnt].header.length = sizeof(__u128);
					entries[tlv_cnt].header.type   = TLV_TYPE_NETMASK6;
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




