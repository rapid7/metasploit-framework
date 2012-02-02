#include "precomp.h"


#ifndef _WIN32

struct iface {
	unsigned char *name;
	unsigned int addr_size;
	unsigned char *addr;
	unsigned char *netmask;
	unsigned char *hwaddr;
	int sa_family;
};

/*
 * Frees an ifaces array returned by get_ifaces
 */
void free_ifaces(struct iface *ifaces, int count) {
	int i;

	if (!ifaces) {
		return;
	}

	dprintf("Freeing %d interfaces", count);

	for (i = 0; i < count; i++) {
		if (ifaces[i].name) {
			free(ifaces[i].name);
		}
		if (ifaces[i].addr) {
			free(ifaces[i].addr);
		}
		if (ifaces[i].netmask) {
			free(ifaces[i].netmask);
		}
		if (ifaces[i].hwaddr) {
			free(ifaces[i].hwaddr);
		}
	}
	free(ifaces);
	return;
}

/*
 * Populates +ifaces+ with an array of iface structs
 *
 * This is very Linux-specific, but hopefully the idea is generic enough that
 * adding support for BSD and other Unixes will at least be possible in the
 * future.
 *
 * Returns 0 on success or an errno if something went wrong.
 * 
 */
int get_ifaces(struct iface **ifaces, int *count) {
	int result;
	struct ifconf ifc = {0};
	struct ifreq *ifr = NULL;
	char buf[1024] = {0};
	int  sck = 0;
	int  i = 0;

	unsigned int num_ifaces = 0;

	/* Get a socket handle to use with all the IOCTL magic below. */
	sck = socket(PF_INET, SOCK_DGRAM, 0);
	if(sck < 0) {
		dprintf("socket: %d: %s", errno, strerror(errno));
		result = errno;
		goto fail;
	}

	/* Query available interfaces. */
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if(ioctl(sck, SIOCGIFCONF, &ifc) < 0) {
		dprintf("ioctl SIOCGIFCONF: %d: %s", errno, strerror(errno));
		result = errno;
		goto fail;
	}

	/* Iterate through the list of interfaces. */
	ifr = ifc.ifc_req;
	num_ifaces = ifc.ifc_len / sizeof(struct ifreq);
	*ifaces = calloc(num_ifaces, sizeof(struct iface));

	*count = num_ifaces;

	for (i = 0; i < num_ifaces; i++) {
		struct ifreq *item = &ifr[i];
		struct sockaddr *addr = &(item->ifr_addr);
		unsigned int addr_size;
		struct iface *iface = &(*ifaces)[i];

		iface->name = malloc(strlen(item->ifr_name)+1);
		memcpy(iface->name, item->ifr_name, strlen(item->ifr_name)+1);

		/*
		 * SIOCGIFCONF will have gotten the name and ip addr, store them
		 */
		switch (addr->sa_family) {
			case AF_INET:
				addr_size = 4;
				iface->addr = malloc(addr_size);
				memcpy(iface->addr, &(((struct sockaddr_in*)addr)->sin_addr), addr_size);
				break;
			case AF_INET6:
				addr_size = 16;
				iface->addr = malloc(addr_size);
				memcpy(iface->addr, &(((struct sockaddr_in6*)addr)->sin6_addr), addr_size);
				break;
			default:
				/* We don't know how to display this thing, it doesn't have an
				 * address, give up.  This will likely result in bogus info in
				 * uninitialized memory being used for the remainder of the
				 * list.
				 *
				 * XXX Should we free this one and try to continue with the rest?
				 */
				result = ENOTSUP;
				goto fail;
		}
		iface->addr_size = addr_size;

		/* Get the MAC address */
		if(ioctl(sck, SIOCGIFHWADDR, item) < 0) {
			dprintf("ioctl SIOCGIFHWADDR: %d: %s", errno, strerror(errno));
			result = errno;
			break;
		}
		iface->hwaddr = malloc(6);
		memcpy(iface->hwaddr, &(item->ifr_hwaddr.sa_data), 6);

		/* Get the netmask */
		if(ioctl(sck, SIOCGIFNETMASK, item) < 0) {
			dprintf("ioctl SIOCGIFNETMASK: %d: %s", errno, strerror(errno));
			result = errno;
			break;
		}
		iface->netmask = malloc(addr_size);
		switch (addr->sa_family) {
			case AF_INET:
				memcpy(iface->netmask, &((struct sockaddr_in*)&(item->ifr_netmask))->sin_addr, addr_size);
				break;
			case AF_INET6:
				memcpy(iface->netmask, &((struct sockaddr_in6*)&(item->ifr_netmask))->sin6_addr, addr_size);
				break;
		}

	}

	return 0;

fail:
	return result;
}

/*
 * mainly for debugging
 */
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
	switch(sa->sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
					s, maxlen);
			break;

		case AF_INET6:
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
					s, maxlen);
			break;

		default:
			strncpy(s, "Unknown AF", maxlen);
			return NULL;
	}

	return s;
}

#endif

/*
 * Returns zero or more local interfaces to the requestor
 */
DWORD request_net_config_get_interfaces(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	DWORD entryCount;

#ifdef _WIN32
	Tlv entries[5];
	PMIB_IPADDRTABLE table = NULL;
	DWORD tableSize = sizeof(MIB_IPADDRROW) * 33;
	DWORD index;

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
	struct iface *ifaces;
	int count;
	int i;
	int if_error;
	Tlv entries[4];

	if_error = get_ifaces(&ifaces, &count);

	if (if_error) {
		result = if_error;
	} else {
		for (i = 0; i < count; i++) {

			entries[0].header.length = strlen(ifaces[i].name)+1;
			entries[0].header.type   = TLV_TYPE_MAC_NAME;
			entries[0].buffer        = (PUCHAR)ifaces[i].name;

			entries[1].header.length = 6;
			entries[1].header.type   = TLV_TYPE_MAC_ADDR;
			entries[1].buffer        = (PUCHAR)ifaces[i].hwaddr;

			entries[2].header.length = ifaces[i].addr_size;
			entries[2].header.type   = TLV_TYPE_IP;
			entries[2].buffer        = (PUCHAR)ifaces[i].addr;

			entries[3].header.length = ifaces[i].addr_size;
			entries[3].header.type   = TLV_TYPE_NETMASK;
			entries[3].buffer        = (PUCHAR)ifaces[i].netmask;
			
			packet_add_tlv_group(response, TLV_TYPE_NETWORK_INTERFACE, entries, 4);
		}
	}

	if (ifaces)
		free_ifaces(ifaces, count);
#endif

	// Transmit the response if valid
	packet_transmit_response(result, remote, response);

	return result;
}




