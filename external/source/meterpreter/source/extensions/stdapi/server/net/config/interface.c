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
	Tlv entries[9];

	if_error = netlink_get_interfaces(&ifaces);

	if (if_error) {
		result = if_error;
	} else {
		for (i = 0; i < ifaces->entries; i++) {

			entries[0].header.length = strlen(ifaces->ifaces[i].name)+1;
			entries[0].header.type   = TLV_TYPE_MAC_NAME;
			entries[0].buffer        = (PUCHAR)ifaces->ifaces[i].name;

			entries[1].header.length = 6;
			entries[1].header.type   = TLV_TYPE_MAC_ADDR;
			entries[1].buffer        = (PUCHAR)ifaces->ifaces[i].hwaddr;

			entries[2].header.length = sizeof(__u32);
			entries[2].header.type   = TLV_TYPE_IP;
			entries[2].buffer        = (PUCHAR)&ifaces->ifaces[i].addr;

			entries[3].header.length = sizeof(__u32);
			entries[3].header.type   = TLV_TYPE_NETMASK;
			entries[3].buffer        = (PUCHAR)&ifaces->ifaces[i].netmask;

			entries[4].header.length = sizeof(__u128);
			entries[4].header.type   = TLV_TYPE_IP6;
			entries[4].buffer        = (PUCHAR)&ifaces->ifaces[i].addr6;

			entries[5].header.length = sizeof(__u128);
			entries[5].header.type   = TLV_TYPE_NETMASK6;
			entries[5].buffer        = (PUCHAR)&ifaces->ifaces[i].netmask6;

			mtu_bigendian            = htonl(ifaces->ifaces[i].mtu);
			entries[6].header.length = sizeof(uint32_t);
			entries[6].header.type   = TLV_TYPE_INTERFACE_MTU;
			entries[6].buffer        = (PUCHAR)&mtu_bigendian;

			entries[7].header.length = strlen(ifaces->ifaces[i].flags)+1;
			entries[7].header.type   = TLV_TYPE_INTERFACE_FLAGS;
			entries[7].buffer        = (PUCHAR)ifaces->ifaces[i].flags;

			interface_index_bigendian = htonl(ifaces->ifaces[i].index);
			entries[8].header.length = sizeof(uint32_t);
			entries[8].header.type   = TLV_TYPE_INTERFACE_INDEX;
			entries[8].buffer        = (PUCHAR)&interface_index_bigendian;
			
			packet_add_tlv_group(response, TLV_TYPE_NETWORK_INTERFACE, entries, 9);
		}
	}

	if (ifaces)
		free(ifaces);
#endif

	// Transmit the response if valid
	packet_transmit_response(result, remote, response);

	return result;
}




