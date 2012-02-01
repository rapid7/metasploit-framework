#include "precomp.h"

#ifndef _WIN32
/*
 * Determine the interfaces MAC address by interface name. It seems that libpcap does not
 * support this natively?
 */
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);

DWORD get_interface_mac_addr(char *interface, unsigned char *mac)
{
	struct ifreq ifr;
	int fd = -1;
	DWORD result = ERROR_NOT_SUPPORTED;

	memset(mac, 0, 6);
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name)-1);
	
	do {
		fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(fd == -1) break;	

		if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
			if(errno) result = errno;
			break;
		}

		memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
		result = 0;
	} while(0);

	if(fd != -1) close(fd);

	return result;
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

#elif 0
	Tlv entries[5]; // xxx, we can probably support more. ip aliases, etc.
	char errbuf[PCAP_ERRBUF_SIZE+4];
	pcap_if_t *interfaces, *iter;
	pcap_addr_t *addresses; 
	unsigned char mac[6];

	interfaces = iter = NULL;

	memset(entries, 0, sizeof(entries));

	do {
		if(pcap_findalldevs(&interfaces, errbuf) == -1) {
			result = ENOMEM; // xxx, send errbuf to remote 
			break;
		}

		for(iter = interfaces; iter != NULL ; iter = iter->next ) {
			entryCount = 0;

			if(strcmp(iter->name, "any") == 0) continue;

			dprintf("[%s] Processing %s", __FUNCTION__, iter->name);

			entries[entryCount].header.length = strlen(iter->name)+1;
			entries[entryCount].header.type   = TLV_TYPE_MAC_NAME;
			entries[entryCount].buffer        = (PUCHAR)iter->name;
			entryCount++;

			for(addresses = iter->addresses ; addresses != NULL ; addresses = addresses->next) {
				struct sockaddr_in *sin;

				dprintf("[%s/%s] addr = %p, netmask = %p, broadaddr = %p, dstaddr = %p", __FUNCTION__, iter->name);
				dprintf("[%s/%s] addresses->addr.sa_family = %d", __FUNCTION__, iter->name, addresses->addr->sa_family);				

				if(addresses->addr == NULL) {
					dprintf("[%s/%s] addresses->addr = NULL ?", __FUNCTION__, iter->name);
					break;
				}

				if(addresses->addr->sa_family == AF_INET) {
					sin = (struct sockaddr_in *)(addresses->addr);

					entries[entryCount].header.length = sizeof(DWORD);
					entries[entryCount].header.type   = TLV_TYPE_IP;
					entries[entryCount].buffer	  = (PUCHAR)&sin->sin_addr.s_addr;
					entryCount++;

					if(addresses->netmask) {
						sin = (struct sockaddr_in *)(addresses->netmask);
						entries[entryCount].header.length = sizeof(DWORD);
						entries[entryCount].header.type   = TLV_TYPE_NETMASK;
						entries[entryCount].buffer        = (PUCHAR)&sin->sin_addr.s_addr;
						entryCount++;
					}



					break;
				}

			}
			
			get_interface_mac_addr(iter->name, mac);

			entries[entryCount].header.length = 6;
			entries[entryCount].header.type   = TLV_TYPE_MAC_ADDR;
			entries[entryCount].buffer        = (PUCHAR)(mac);
			entryCount++;
			

			dprintf("[%s] adding response with %d entries", __FUNCTION__, entryCount);
			packet_add_tlv_group(response, TLV_TYPE_NETWORK_INTERFACE, entries, entryCount);
			dprintf("[%s] done with adding", __FUNCTION__);
		}
		
	} while(0);

	if(interfaces) {
		dprintf("[%s] calling pcap_freealldevs()", __FUNCTION__);
		pcap_freealldevs(interfaces);
	}

	dprintf("[%s] and done!", __FUNCTION__);

#else
	// List of TLVs used for each interface.  Will contain name, mac addr, ip addr, netmask
	Tlv entries[5];

	struct ifconf ifc = {0};
	struct ifreq *ifr = NULL;
	char buf[1024] = {0};
	int  sck = 0;
	int  i = 0;
	unsigned int num_ifaces = 0;

	do {
		/* Get a socket handle. */
		sck = socket(PF_INET, SOCK_DGRAM, 0);
		if(sck < 0) {
			dprintf("socket: %d: %s", errno, strerror(errno));
			result = errno;
			break;
		}

		/* Query available interfaces. */
		ifc.ifc_len = sizeof(buf);
		ifc.ifc_buf = buf;
		if(ioctl(sck, SIOCGIFCONF, &ifc) < 0) {
			dprintf("ioctl SIOCGIFCONF: %d: %s", errno, strerror(errno));
			result = errno;
			break;
		}

		/* Iterate through the list of interfaces. */
		ifr = ifc.ifc_req;
		num_ifaces = ifc.ifc_len / sizeof(struct ifreq);

		for(i = 0; i < num_ifaces; i++)
		{
			struct ifreq *item = &ifr[i];
			struct sockaddr *addr = &(item->ifr_addr);
			unsigned int entryCount = 0;
			unsigned int addr_size;

			switch (addr->sa_family) {
				case AF_INET:
					addr_size = 4;
					entries[entryCount].buffer = malloc(addr_size);
					memcpy(entries[entryCount].buffer, ((PUCHAR)&(((struct sockaddr_in*)addr)->sin_addr)), addr_size);
					break;
				case AF_INET6:
					addr_size = 16;
					entries[entryCount].buffer = malloc(addr_size);
					memcpy(entries[entryCount].buffer, &(((struct sockaddr_in6*)addr)->sin6_addr), addr_size);
					break;
			}
			entries[entryCount].header.length = addr_size;
			entries[entryCount].header.type   = TLV_TYPE_IP;
			entryCount++;

			entries[entryCount].header.length = strlen(item->ifr_name)+1;
			entries[entryCount].header.type   = TLV_TYPE_MAC_NAME;
			entries[entryCount].buffer        = (PUCHAR)malloc(strlen(item->ifr_name)+1);
			memcpy(entries[entryCount].buffer, item->ifr_name, strlen(item->ifr_name)+1);
			entryCount++;

			/* Get the MAC address */
			if(ioctl(sck, SIOCGIFHWADDR, item) < 0) {
				dprintf("ioctl SIOCGIFHWADDR: %d: %s", errno, strerror(errno));
				result = errno;
				break;
			}
			entries[entryCount].header.length = 6;
			entries[entryCount].header.type   = TLV_TYPE_MAC_ADDR;
			entries[entryCount].buffer        = malloc(6);
			memcpy(entries[entryCount].buffer, &(item->ifr_hwaddr.sa_data), 6);
			entryCount++;

			/* Get the netmask */
			if(ioctl(sck, SIOCGIFNETMASK, item) < 0) {
				dprintf("ioctl SIOCGIFNETMASK: %d: %s", errno, strerror(errno));
				result = errno;
				break;
			}
			entries[entryCount].header.length = addr_size;
			entries[entryCount].header.type   = TLV_TYPE_NETMASK;
			entries[entryCount].buffer        = malloc(addr_size);
			switch (addr->sa_family) {
				case AF_INET:
					memcpy(entries[entryCount].buffer, &((struct sockaddr_in*)&(item->ifr_netmask))->sin_addr, addr_size);
					break;
				case AF_INET6:
					memcpy(entries[entryCount].buffer, &((struct sockaddr_in6*)&(item->ifr_netmask))->sin6_addr, addr_size);
					break;
			}
			entryCount++;

			packet_add_tlv_group(response, TLV_TYPE_NETWORK_INTERFACE, entries, entryCount);

		}
	} while (0);

#endif

	// Transmit the response if valid
	packet_transmit_response(result, remote, response);
	dprintf("after transmit");

	for (i = 0; i < entryCount; i++) {

	}

	return result;
}


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
