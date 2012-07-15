#include "precomp.h"

#ifdef _WIN32

DWORD windows_get_arp_table(Remote *remote, Packet *response) 
{
	PMIB_IPNETTABLE pIpNetTable = NULL;
	DWORD result = ERROR_SUCCESS;
	DWORD dwSize = 0;
	DWORD dwRetVal;
	DWORD i;
	char interface_index[10];

	do {
		dwRetVal = GetIpNetTable(NULL, &dwSize, 0);

		/* Get the size required by GetIpNetTable() */
		if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
			pIpNetTable = (MIB_IPNETTABLE *) malloc (dwSize);
		}

		else if ((dwRetVal != NO_ERROR) && (dwRetVal != ERROR_NO_DATA)) {
			result = ERROR_NOT_SUPPORTED;
			break;
		}

		if (pIpNetTable == NULL) {
			result = GetLastError();
			break;
		}
		
		if ((dwRetVal = GetIpNetTable(pIpNetTable, &dwSize, 0)) == NO_ERROR) {
			dprintf("[ARP] found %d arp entries", pIpNetTable->dwNumEntries);
			for (i = 0 ; i < pIpNetTable->dwNumEntries ; i++) {
				// send only dynamic or static entry
				if ((pIpNetTable->table[i].dwType == MIB_IPNET_TYPE_DYNAMIC) || 
					(pIpNetTable->table[i].dwType == MIB_IPNET_TYPE_STATIC)) {
					Tlv arp[3];
					// can't send interface name as it can be _big_, so send index instead
					sprintf_s(interface_index, sizeof(interface_index), "%d", pIpNetTable->table[i].dwIndex);

					arp[0].header.type	= TLV_TYPE_IP;
					arp[0].header.length 	= sizeof(DWORD);
					arp[0].buffer 		= (PUCHAR)&pIpNetTable->table[i].dwAddr;
	
					arp[1].header.type	= TLV_TYPE_MAC_ADDR;
					arp[1].header.length	= 6;
					arp[1].buffer		= (PUCHAR)pIpNetTable->table[i].bPhysAddr;
	
					arp[2].header.type	= TLV_TYPE_MAC_NAME;
					arp[2].header.length	= strlen(interface_index) + 1; 
					arp[2].buffer		= (PUCHAR)interface_index;
		
					packet_add_tlv_group(response, TLV_TYPE_ARP_ENTRY, arp, 3);
				}
			}
			free(pIpNetTable);
		}
		else { // GetIpNetTable failed
			result = GetLastError();
			break;
		}
	} while (0);

	return result;
}
#else

DWORD linux_proc_get_arp_table(struct arp_table ** table_arp)
{
	unsigned char buffer_ip[40], buffer_mac[40], buffer_int[40];
	char * end_ptr;
	DWORD result = ERROR_SUCCESS;
	FILE * fd;
	__u32 newsize, i;
	long b;
	struct arp_table * table_tmp;
	struct in_addr ip_addr;

	fd = fopen("/proc/net/arp", "r");
	if (fd == NULL) {
		result = GetLastError();
		return result;
	}

	*table_arp = calloc(sizeof(struct arp_table), 1);

	/*
	 * read first line that we don't need
	 * IP address       HW type     Flags       HW address            Mask     Device
	 */
	while (!feof(fd) && fgetc(fd) != '\n');
	while (!feof(fd) && (fscanf(fd, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %30s", buffer_ip, buffer_mac, buffer_int) == 3)) {
		
		// allocate size for new entry
		newsize = sizeof(struct arp_table);
		newsize += ((*table_arp)->entries + 1) * sizeof(struct arp_entry);
		table_tmp = realloc(*table_arp, newsize);
		if (table_tmp == NULL)
			return ENOMEM;

		memset(&table_tmp->table[table_tmp->entries], 0, sizeof(struct arp_entry));

		// ip address
		inet_pton(AF_INET, buffer_ip, &ip_addr);
		table_tmp->table[table_tmp->entries].ipaddr = ip_addr.s_addr;
			
		// mac address
		for(i = 0; i < 6 ; i++) {
			b = strtol(&buffer_mac[3*i], 0, 16);
			table_tmp->table[table_tmp->entries].hwaddr[i] = (unsigned char)b;
		}	 

		// interface name
		strncpy(table_tmp->table[table_tmp->entries].name, buffer_int, IFNAMSIZ);

		table_tmp->entries++;
		*table_arp = table_tmp;

	}	

	fclose(fd);
	return result;
}

DWORD linux_get_arp_table(Remote *remote, Packet *response)
{
	struct arp_table *table_arp = NULL;
	DWORD result;
	DWORD index;


	dprintf("getting arp table through /proc/net/arp");
	result = linux_proc_get_arp_table(&table_arp);
	dprintf("result = %d, table_arp = 0x%p , entries : %d", result, table_arp, table_arp->entries);

	for(index = 0; index < table_arp->entries; index++) {
		Tlv arp[3];

		arp[0].header.type	= TLV_TYPE_IP;
		arp[0].header.length 	= sizeof(__u32);
		arp[0].buffer 		= (PUCHAR)&table_arp->table[index].ipaddr;
	
		arp[1].header.type	= TLV_TYPE_MAC_ADDR;
		arp[1].header.length	= 6;
		arp[1].buffer		= (PUCHAR)(table_arp->table[index].hwaddr);
	
		arp[2].header.type	= TLV_TYPE_MAC_NAME;
		arp[2].header.length	= strlen(table_arp->table[index].name) + 1; 
		arp[2].buffer		= (PUCHAR)(table_arp->table[index].name);
		
		packet_add_tlv_group(response, TLV_TYPE_ARP_ENTRY, arp, 3);
	}
	dprintf("sent %d arp entries", table_arp->entries);

	if (table_arp)
		free(table_arp);

	return result;
}

#endif

/*
 * Returns zero or more arp entries to the requestor from the arp cache
 */
DWORD request_net_config_get_arp_table(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result;

#ifdef _WIN32
	result = windows_get_arp_table(remote, response);
#else 
	result = linux_get_arp_table(remote, response);
#endif

	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

