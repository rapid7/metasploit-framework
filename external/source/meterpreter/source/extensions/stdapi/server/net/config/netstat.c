#include "precomp.h"

#ifdef _WIN32

/*
 * check if there is enough place for another connection entry and allocate some more
 * memory if necessary
 */
DWORD check_and_allocate(struct connection_table **table_connection)
{
	DWORD newsize;
	struct connection_table * tmp_table;

	if ((*table_connection)->entries >= (*table_connection)->max_entries) {
			newsize = sizeof(struct connection_table);
			newsize += ((*table_connection)->entries + 10) * sizeof(struct connection_entry);
			tmp_table = (struct connection_table *)realloc(*table_connection, newsize);
			if (tmp_table == NULL) {
				free(*table_connection);
				return ERROR_NOT_ENOUGH_MEMORY;
			}

			*table_connection = tmp_table;
			memset(&(*table_connection)->table[(*table_connection)->entries], 0, 10 * sizeof(struct connection_entry));
			(*table_connection)->max_entries += 10;
	}
	return ERROR_SUCCESS;
}

typedef HANDLE (WINAPI *ptr_CreateToolhelp32Snapshot)(DWORD dwFlags,DWORD th32ProcessID);
typedef BOOL (WINAPI *ptr_Process32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL (WINAPI *ptr_Process32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);


/*
 * write pid/process_name in buffer
 */

DWORD set_process_name(DWORD pid, char * buffer, DWORD buffer_size)
{
	HANDLE hSnapshot;
	ptr_CreateToolhelp32Snapshot ct32s = NULL;
	ptr_Process32First p32f = NULL;
	ptr_Process32Next p32n = NULL;


	ct32s = (ptr_CreateToolhelp32Snapshot)GetProcAddress(GetModuleHandle("kernel32"), "CreateToolhelp32Snapshot");
	p32f = (ptr_Process32First)GetProcAddress(GetModuleHandle("kernel32"), "Process32First");
	p32n = (ptr_Process32Next)GetProcAddress(GetModuleHandle("kernel32"), "Process32Next");

	if ((!ct32s) || (!p32f) || (!p32n))
		return -1;

	hSnapshot = ct32s(TH32CS_SNAPPROCESS,0);
	if(hSnapshot) {
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if(p32f(hSnapshot,&pe32)) {
			do {
				if (pe32.th32ProcessID == pid) {
					_snprintf_s(buffer, buffer_size-1, _TRUNCATE, "%d/%s",pid, pe32.szExeFile);
					break;
				}
            } while(p32n(hSnapshot,&pe32));
         }
         CloseHandle(hSnapshot);
    }
	return ERROR_SUCCESS;
}

char *tcp_connection_states[] = {
   "", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
   "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB", "UNKNOWN" };

typedef struct _MIB_TCP6ROW_OWNER_MODULE {
  UCHAR         ucLocalAddr[16];
  DWORD         dwLocalScopeId;
  DWORD         dwLocalPort;
  UCHAR         ucRemoteAddr[16];
  DWORD         dwRemoteScopeId;
  DWORD         dwRemotePort;
  DWORD         dwState;
  DWORD         dwOwningPid;
  LARGE_INTEGER liCreateTimestamp;
  ULONGLONG     OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE];
} MIB_TCP6ROW_OWNER_MODULE, *PMIB_TCP6ROW_OWNER_MODULE;

typedef struct _MIB_UDP6ROW_OWNER_MODULE {
  UCHAR         ucLocalAddr[16];
  DWORD         dwLocalScopeId;
  DWORD         dwLocalPort;
  DWORD         dwOwningPid;
  LARGE_INTEGER liCreateTimestamp;
  union {
    struct {
      int SpecificPortBind  :1;
    };
    int    dwFlags;
  };
  ULONGLONG     OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE];
} MIB_UDP6ROW_OWNER_MODULE, *PMIB_UDP6ROW_OWNER_MODULE;

typedef struct _MIB_TCP6TABLE_OWNER_MODULE {
  DWORD                    dwNumEntries;
  MIB_TCP6ROW_OWNER_MODULE table[ANY_SIZE];
} MIB_TCP6TABLE_OWNER_MODULE, *PMIB_TCP6TABLE_OWNER_MODULE;

typedef struct {
  DWORD                    dwNumEntries;
  MIB_UDP6ROW_OWNER_MODULE table[ANY_SIZE];
} MIB_UDP6TABLE_OWNER_MODULE, *PMIB_UDP6TABLE_OWNER_MODULE;

typedef DWORD (WINAPI * ptr_GetExtendedTcpTable)(PVOID, PDWORD pdwSize, BOOL bOrder, ULONG ulAf,TCP_TABLE_CLASS TableClass,
ULONG Reserved);
typedef DWORD (WINAPI * ptr_GetExtendedUdpTable)(PVOID, PDWORD pdwSize, BOOL bOrder, ULONG ulAf,TCP_TABLE_CLASS TableClass,
ULONG Reserved);


/*
 * retrieve tcp table for win 2000 and NT4 ?
 */
DWORD windows_get_tcp_table_win2000_down(struct connection_table **table_connection)
{
	PMIB_TCPTABLE pTcpTable = NULL;
	struct connection_entry * current_connection;
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;
	DWORD result = ERROR_SUCCESS;
	DWORD i, state;

	do {
		dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE);
		dprintf("[NETSTAT TCP] need %d bytes",dwSize);
		/* Get the size required by GetTcpTable() */
		if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
			pTcpTable = (MIB_TCPTABLE *) malloc (dwSize);
		}
		else if (dwRetVal != NO_ERROR) {
				result = ERROR_NOT_SUPPORTED;
				break;
		}

		if ((dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
			dprintf("[NETSTAT] found %d tcp connections", pTcpTable->dwNumEntries);
			for (i = 0 ; i < pTcpTable->dwNumEntries ; i++) {
				// check available memory and allocate if necessary
				if (check_and_allocate(table_connection) == ERROR_NOT_ENOUGH_MEMORY) {
					free(pTcpTable);
					return ERROR_NOT_ENOUGH_MEMORY;
				}
				current_connection = &(*table_connection)->table[(*table_connection)->entries];
				current_connection->type             = AF_INET;
				current_connection->local_addr.addr  = pTcpTable->table[i].dwLocalAddr;
				current_connection->remote_addr.addr = pTcpTable->table[i].dwRemoteAddr;
				current_connection->local_port       = ntohs((u_short)(pTcpTable->table[i].dwLocalPort & 0x0000ffff));
				// if socket is in LISTEN, remote_port is garbage, force value to 0
				if (pTcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN)
					current_connection->remote_port  = 0;
				else
					current_connection->remote_port  = ntohs((u_short)(pTcpTable->table[i].dwRemotePort & 0x0000ffff));

				state = pTcpTable->table[i].dwState;
				if ((state <= 0) || (state > 12))
					state = 13; // points to UNKNOWN in the state array
				strncpy(current_connection->state, tcp_connection_states[state], sizeof(current_connection->state));
				strncpy(current_connection->protocol, "tcp", sizeof(current_connection->protocol));

				// force program_name to "-"
				strncpy(current_connection->program_name, "-", sizeof(current_connection->program_name));

				(*table_connection)->entries++;
			}
			free(pTcpTable);
		}
		else { // GetTcpTable failed
			result = GetLastError();
			break;
		}
	} while (0) ;

	return result;
}

/*
 * retrieve tcp table for win xp and up
 */
DWORD windows_get_tcp_table(struct connection_table **table_connection)
{
	DWORD result = ERROR_SUCCESS;
	struct connection_entry * current_connection = NULL;
	MIB_TCPTABLE_OWNER_MODULE  * tablev4 = NULL;
	MIB_TCP6TABLE_OWNER_MODULE * tablev6 = NULL;
	MIB_TCPROW_OWNER_MODULE  * currentv4 = NULL;
	MIB_TCP6ROW_OWNER_MODULE * currentv6 = NULL;
	DWORD i, state, dwSize;


	ptr_GetExtendedTcpTable gett            = NULL;

	gett    = (ptr_GetExtendedTcpTable)GetProcAddress(GetModuleHandle("iphlpapi"), "GetExtendedTcpTable");

	// systems that don't support GetExtendedTcpTable
	if (gett == NULL) {
		return windows_get_tcp_table_win2000_down(table_connection);
	}
	do {
		// IPv4 part
		dwSize = 0;
		if (gett(NULL,&dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
			tablev4 = (MIB_TCPTABLE_OWNER_MODULE *)malloc(dwSize);
			if (gett(tablev4, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0) == NO_ERROR) {
				for(i=0; i<tablev4->dwNumEntries; i++) {
					// check available memory and allocate if necessary
					if (check_and_allocate(table_connection) == ERROR_NOT_ENOUGH_MEMORY) {
						free(tablev4);
						return ERROR_NOT_ENOUGH_MEMORY;
					}
					currentv4 = &tablev4->table[i];
					current_connection = &(*table_connection)->table[(*table_connection)->entries];
					current_connection->type             = AF_INET;
					current_connection->local_addr.addr  = currentv4->dwLocalAddr;
					current_connection->remote_addr.addr = currentv4->dwRemoteAddr;
					current_connection->local_port       = ntohs((u_short)(currentv4->dwLocalPort & 0x0000ffff));
					// if socket is in LISTEN, remote_port is garbage, force value to 0
					if (currentv4->dwState == MIB_TCP_STATE_LISTEN)
						current_connection->remote_port  = 0;
					else
						current_connection->remote_port  = ntohs((u_short)(currentv4->dwRemotePort & 0x0000ffff));

					state = currentv4->dwState;
					if ((state <= 0) || (state > 12))
						state = 13; // points to UNKNOWN in the state array
					strncpy(current_connection->state, tcp_connection_states[state], sizeof(current_connection->state));
					strncpy(current_connection->protocol, "tcp", sizeof(current_connection->protocol));

					// force program_name to "-" and try to get real name through GetOwnerModuleFromXXXEntry
					strncpy(current_connection->program_name, "-", sizeof(current_connection->program_name));

					set_process_name(currentv4->dwOwningPid, current_connection->program_name, sizeof(current_connection->program_name));

					(*table_connection)->entries++;
				}
			}
			else { // gett failed
				result = GetLastError();
				if (tablev4)
					free(tablev4);
				break;
			}
			if (tablev4)
				free(tablev4);
		}
		// IPv6 part
		dwSize = 0;
		if (gett(NULL,&dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
			tablev6 = (MIB_TCP6TABLE_OWNER_MODULE *)malloc(dwSize);
			if (gett(tablev6, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0) == NO_ERROR) {
				for(i=0; i<tablev6->dwNumEntries; i++) {
					// check available memory and allocate if necessary
					if (check_and_allocate(table_connection) == ERROR_NOT_ENOUGH_MEMORY) {
						free(tablev6);
						return ERROR_NOT_ENOUGH_MEMORY;
					}
					currentv6 = &tablev6->table[i];
					current_connection = &(*table_connection)->table[(*table_connection)->entries];
					current_connection->type             = AF_INET6;
					memcpy(&current_connection->local_addr.addr6, currentv6->ucLocalAddr, sizeof(current_connection->local_addr.addr6));
					memcpy(&current_connection->remote_addr.addr6, currentv6->ucRemoteAddr, sizeof(current_connection->remote_addr.addr6));
					current_connection->local_port       = ntohs((u_short)(currentv6->dwLocalPort & 0x0000ffff));
					// if socket is in LISTEN, remote_port is garbage, force value to 0
					if (currentv6->dwState == MIB_TCP_STATE_LISTEN)
						current_connection->remote_port  = 0;
					else
						current_connection->remote_port  = ntohs((u_short)(currentv6->dwRemotePort & 0x0000ffff));

					state = currentv6->dwState;
					if ((state <= 0) || (state > 12))
						state = 13; // points to UNKNOWN in the state array
					strncpy(current_connection->state, tcp_connection_states[state], sizeof(current_connection->state));
					strncpy(current_connection->protocol, "tcp6", sizeof(current_connection->protocol));

					// force program_name to "-" and try to get real name through GetOwnerModuleFromXXXEntry
					strncpy(current_connection->program_name, "-", sizeof(current_connection->program_name));

					set_process_name(currentv6->dwOwningPid, current_connection->program_name, sizeof(current_connection->program_name));

					(*table_connection)->entries++;
				}
			}
			else { // gett failed
				result = GetLastError();
				if (tablev6)
					free(tablev6);
				break;
			}
			if (tablev6)
				free(tablev6);
		}

	} while (0);
	return result;
}

/*
 * retrieve udp table for win 2000 and NT4 ?
 */
DWORD windows_get_udp_table_win2000_down(struct connection_table **table_connection)
{
	PMIB_UDPTABLE pUdpTable = NULL;
	struct connection_entry * current_connection;
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;
	DWORD result = ERROR_SUCCESS;
	DWORD i;

	do {
		dwRetVal = GetUdpTable(pUdpTable, &dwSize, TRUE);
		dprintf("[NETSTAT UDP] need %d bytes",dwSize);
		/* Get the size required by GetUdpTable() */
		if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
			pUdpTable = (MIB_UDPTABLE *) malloc (dwSize);
		}
		else if (dwRetVal != NO_ERROR) {
				result = ERROR_NOT_SUPPORTED;
				break;
		}

		if ((dwRetVal = GetUdpTable(pUdpTable, &dwSize, TRUE)) == NO_ERROR) {
			dprintf("[NETSTAT] found %d udp connections", pUdpTable->dwNumEntries);
			for (i = 0 ; i < pUdpTable->dwNumEntries ; i++) {
				// check available memory and allocate if necessary
				if (check_and_allocate(table_connection) == ERROR_NOT_ENOUGH_MEMORY) {
					free(pUdpTable);
					return ERROR_NOT_ENOUGH_MEMORY;
				}
				// GetUdpTable reports only listening UDP sockets, not "active" ones
				current_connection = &(*table_connection)->table[(*table_connection)->entries];
				current_connection->type             = AF_INET;
				current_connection->local_addr.addr  = pUdpTable->table[i].dwLocalAddr;
				current_connection->remote_addr.addr = 0;
				current_connection->local_port       = ntohs((u_short)(pUdpTable->table[i].dwLocalPort & 0x0000ffff));
				current_connection->remote_port      = 0;

				// force state to ""
				strncpy(current_connection->state, "", sizeof(current_connection->state));
				strncpy(current_connection->protocol, "udp", sizeof(current_connection->protocol));

				// force program_name to "-"
				strncpy(current_connection->program_name, "-", sizeof(current_connection->program_name));

				(*table_connection)->entries++;
			}
			free(pUdpTable);
		}
		else { // GetUdpTable failed
			result = GetLastError();
			break;
		}
	} while (0) ;

	return result;
}


/*
 * retrieve udp table for win xp and up
 */
DWORD windows_get_udp_table(struct connection_table **table_connection)
{
	DWORD result = ERROR_SUCCESS;
	struct connection_entry * current_connection = NULL;
	MIB_UDPTABLE_OWNER_MODULE  * tablev4 = NULL;
	MIB_UDP6TABLE_OWNER_MODULE * tablev6 = NULL;
	MIB_UDPROW_OWNER_MODULE  * currentv4 = NULL;
	MIB_UDP6ROW_OWNER_MODULE * currentv6 = NULL;
	DWORD i, dwSize;

	ptr_GetExtendedUdpTable geut            = NULL;

	geut    = (ptr_GetExtendedTcpTable)GetProcAddress(GetModuleHandle("iphlpapi"), "GetExtendedUdpTable");

	// systems that don't support GetExtendedUdpTable
	if (geut == NULL) {
		return windows_get_udp_table_win2000_down(table_connection);
	}
	do {
		// IPv4 part
		dwSize = 0;
		if (geut(NULL,&dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_MODULE, 0) == ERROR_INSUFFICIENT_BUFFER) {
			tablev4 = (MIB_UDPTABLE_OWNER_MODULE *)malloc(dwSize);
			if (geut(tablev4, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_MODULE, 0) == NO_ERROR) {
				for(i=0; i<tablev4->dwNumEntries; i++) {
					// check available memory and allocate if necessary
					if (check_and_allocate(table_connection) == ERROR_NOT_ENOUGH_MEMORY) {
						free(tablev4);
						return ERROR_NOT_ENOUGH_MEMORY;
					}
					// GetExtendedUdpTable reports only listening UDP sockets, not "active" ones
					currentv4 = &tablev4->table[i];
					current_connection = &(*table_connection)->table[(*table_connection)->entries];
					current_connection->type             = AF_INET;
					current_connection->local_addr.addr  = currentv4->dwLocalAddr;
					current_connection->remote_addr.addr = 0;
					current_connection->local_port       = ntohs((u_short)(currentv4->dwLocalPort & 0x0000ffff));
					current_connection->remote_port  = 0;

					strncpy(current_connection->state, "", sizeof(current_connection->state));
					strncpy(current_connection->protocol, "udp", sizeof(current_connection->protocol));

					// force program_name to "-" and try to get real name through GetOwnerModuleFromXXXEntry
					strncpy(current_connection->program_name, "-", sizeof(current_connection->program_name));

					set_process_name(currentv4->dwOwningPid, current_connection->program_name, sizeof(current_connection->program_name));

					(*table_connection)->entries++;
				}
			}
			else { // geut failed
				result = GetLastError();
				if (tablev4)
					free(tablev4);
				break;
			}
			if (tablev4)
				free(tablev4);
		}
		// IPv6 part
		dwSize = 0;
		if (geut(NULL,&dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0) == ERROR_INSUFFICIENT_BUFFER) {
			tablev6 = (MIB_UDP6TABLE_OWNER_MODULE *)malloc(dwSize);
			if (geut(tablev6, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0) == NO_ERROR) {
				for(i=0; i<tablev6->dwNumEntries; i++) {
					// check available memory and allocate if necessary
					if (check_and_allocate(table_connection) == ERROR_NOT_ENOUGH_MEMORY) {
						free(tablev6);
						return ERROR_NOT_ENOUGH_MEMORY;
					}
					currentv6 = &tablev6->table[i];
					current_connection = &(*table_connection)->table[(*table_connection)->entries];
					current_connection->type          = AF_INET6;
					memcpy(&current_connection->local_addr.addr6, currentv6->ucLocalAddr, sizeof(current_connection->local_addr.addr6));
					memset(&current_connection->remote_addr.addr6, 0, sizeof(current_connection->remote_addr.addr6));
					current_connection->local_port   = ntohs((u_short)(currentv6->dwLocalPort & 0x0000ffff));
					current_connection->remote_port  = 0;

					strncpy(current_connection->state, "", sizeof(current_connection->state));
					strncpy(current_connection->protocol, "udp6", sizeof(current_connection->protocol));

					// force program_name to "-" and try to get real name through GetOwnerModuleFromXXXEntry
					strncpy(current_connection->program_name, "-", sizeof(current_connection->program_name));

					set_process_name(currentv6->dwOwningPid, current_connection->program_name, sizeof(current_connection->program_name));

					(*table_connection)->entries++;
				}
			}
			else { // gett failed
				result = GetLastError();
				if (tablev6)
					free(tablev6);
				break;
			}
			if (tablev6)
				free(tablev6);
		}

	} while (0);
	return result;

}



DWORD windows_get_connection_table(Remote *remote, Packet *response)
{
	struct connection_table *table_connection = NULL;
	struct connection_entry * current_connection;
	DWORD dwRetVal;
	int index;
	DWORD local_port_be, remote_port_be;

	table_connection = (struct connection_table *)calloc(sizeof(struct connection_table) + 10 * sizeof(struct connection_entry), 1);
	table_connection->max_entries = 10;

	dwRetVal = windows_get_tcp_table(&table_connection);
	if (dwRetVal == ERROR_NOT_ENOUGH_MEMORY)
		return ERROR_NOT_ENOUGH_MEMORY;

	dwRetVal = windows_get_udp_table(&table_connection);
	if (dwRetVal == ERROR_NOT_ENOUGH_MEMORY)
		return ERROR_NOT_ENOUGH_MEMORY;


	for(index = 0; index < table_connection->entries; index++) {
		Tlv connection[7];
		current_connection = &table_connection->table[index];
		if (current_connection->type == AF_INET) {
			connection[0].header.type      = TLV_TYPE_LOCAL_HOST_RAW;
			connection[0].header.length    = sizeof(__u32);
			connection[0].buffer           = (PUCHAR)&current_connection->local_addr.addr;

			connection[1].header.type      = TLV_TYPE_PEER_HOST_RAW;
			connection[1].header.length    = sizeof(__u32);
			connection[1].buffer           = (PUCHAR)&current_connection->remote_addr.addr;
		}
		else {
			connection[0].header.type      = TLV_TYPE_LOCAL_HOST_RAW;
			connection[0].header.length    = sizeof(__u128);
			connection[0].buffer           = (PUCHAR)&current_connection->local_addr.addr6;

			connection[1].header.type      = TLV_TYPE_PEER_HOST_RAW;
			connection[1].header.length    = sizeof(__u128);
			connection[1].buffer           = (PUCHAR)&current_connection->remote_addr.addr6;
		}

		local_port_be = htonl(current_connection->local_port);
		connection[2].header.type      = TLV_TYPE_LOCAL_PORT;
		connection[2].header.length    = sizeof(__u32);
		connection[2].buffer           = (PUCHAR)&local_port_be;

		remote_port_be = htonl(current_connection->remote_port);
		connection[3].header.type      = TLV_TYPE_PEER_PORT;
		connection[3].header.length    = sizeof(__u32);
		connection[3].buffer           = (PUCHAR)&remote_port_be;

		connection[4].header.type      = TLV_TYPE_MAC_NAME;
		connection[4].header.length    = strlen(current_connection->protocol) + 1;
		connection[4].buffer           = (PUCHAR)(current_connection->protocol);

		connection[5].header.type      = TLV_TYPE_SUBNET_STRING;
		connection[5].header.length    = strlen(current_connection->state) + 1;
		connection[5].buffer           = (PUCHAR)(current_connection->state);

		connection[6].header.type      = TLV_TYPE_PROCESS_NAME;
		connection[6].header.length    = strlen(current_connection->program_name) + 1;
		connection[6].buffer           = (PUCHAR)(current_connection->program_name);

		packet_add_tlv_group(response, TLV_TYPE_NETSTAT_ENTRY, connection, 7);
	}
	dprintf("sent %d connections", table_connection->entries);

	if (table_connection)
		free(table_connection);

	return ERROR_SUCCESS;
}

#else

#include <sys/types.h>
#include <dirent.h>

char *tcp_connection_states[] = {
   "", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT",
   "CLOSED", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "UNKNOWN"
};
char *udp_connection_states[] = {
   "", "ESTABLISHED", "", "", "", "", "", "", "", "", "", "", "UNKNOWN"
};


DWORD linux_parse_proc_net_file(char * filename, struct connection_table ** table_connection, char type, char * protocol, char tableidx )
{
	struct connection_table * tmp_table;
	struct connection_entry * current_connection;
	char ** connection_states;
	FILE * fd;
	char buffer[300], buffer_junk[100];
	__u32 local_addr, remote_addr;
	__u128 local_addr6, remote_addr6;
	__u32 local_port, remote_port;
	__u32 state, uid, inode;
	__u32 newsize;

	fd = fopen(filename, "r");
	if (fd == NULL)
		return -1;

	if (tableidx == 0) // TCP states
		connection_states = tcp_connection_states;
	else // UDP states
		connection_states = udp_connection_states;

	 /*
         * read first line that we don't need
	 * sl  local_address  remote_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
         */
        while (!feof(fd) && fgetc(fd) != '\n');
	while (!feof(fd) && (fgets(buffer, sizeof(buffer), fd) != NULL)) {
		if ((*table_connection)->entries >= (*table_connection)->max_entries) {
			newsize = sizeof(struct connection_table);
			newsize += ((*table_connection)->entries + 10) * sizeof(struct connection_entry);
			tmp_table = realloc(*table_connection, newsize);
			*table_connection = tmp_table;
			memset(&(*table_connection)->table[(*table_connection)->entries], 0, 10 * sizeof(struct connection_entry));
			(*table_connection)->max_entries += 10;
		}

		current_connection = &(*table_connection)->table[(*table_connection)->entries];

		if (type == AF_INET) {
			if (sscanf(buffer, " %*u: %lX:%x %lX:%x %x %*X:%*X %*x:%*X %*x %u %*u %u %[^\n] ", &local_addr, &local_port,
				&remote_addr, &remote_port, &state, &uid, &inode, buffer_junk) == 8) {

				current_connection->local_addr.addr  = local_addr;
				current_connection->remote_addr.addr = remote_addr;
			}
			else
				continue;
		}
		else { // AF_INET6
			if (sscanf(buffer, " %*u: %08X%08X%08X%08X:%x %08X%08x%08X%08X:%x %x %*X:%*X %*x:%*X %*x %u %*u %u %[^\n] ", &local_addr6.a1,
				&local_addr6.a2,&local_addr6.a3, &local_addr6.a4, &local_port, &remote_addr6.a1, &remote_addr6.a2, &remote_addr6.a3,
				&remote_addr6.a4,&remote_port, &state, &uid, &inode, buffer_junk) == 14) {
				memcpy(&current_connection->local_addr.addr6,  &local_addr6, sizeof(__u128));
				memcpy(&current_connection->remote_addr.addr6, &remote_addr6, sizeof(__u128));
			}
			else
				continue;
		}

		current_connection->type        = type;
		current_connection->local_port  = local_port;
		current_connection->remote_port = remote_port;
		current_connection->uid         = uid;
		current_connection->inode       = inode;
		// protocol such as tcp/tcp6/udp/udp6
		strncpy(current_connection->protocol, protocol,	sizeof(current_connection->protocol));
		if ((state < 0) && (state > 11))
			state = 12; // points to UNKNOWN in the table

		// state, number to string : 0x0A --> LISTEN
		strncpy(current_connection->state, connection_states[state], sizeof(current_connection->state));

		// initialize every program_name to "-", will be changed if we find the good info in /proc
		strncpy(current_connection->program_name, "-", sizeof(current_connection->program_name));

		(*table_connection)->entries++;
	}
	fclose(fd);
	return 0;
}

DWORD linux_proc_get_program_name(struct connection_entry * connection, unsigned char * pid)
{
	FILE *fd;
	char buffer[30], buffer_file[256], name[256];
	char * bname;
	int do_status = 0;

	do {
		// try /proc/PID/cmdline first
		snprintf(buffer, sizeof(buffer)-1, "/proc/%s/cmdline", pid);
		fd = fopen(buffer, "r");

		// will try /proc/PID/status
		if (fd == NULL) {
			do_status = 1;
			break;
		}
		if (fgets(buffer_file, sizeof(buffer_file), fd) == NULL) {
			do_status = 1;
			break;
		}
		// each entry in cmdline is seperated by '\0' so buffer_file contains first the path of the executable launched
		if ((bname = basename(buffer_file)) == NULL) {
			do_status = 1;
			break;
		}
		// copy basename into name to be consistent at the end
		strncpy(name, bname, sizeof(name)-1);
		name[sizeof(name)-1] = '\0';

	} while (0);

	if (fd != NULL)
		fclose(fd);


	// /proc/PID/cmdline failed, try /proc/PID/status
	if (do_status == 1) {
		snprintf(buffer, sizeof(buffer)-1, "/proc/%s/status", pid);
		fd = fopen(buffer, "r");

		// will try /proc/PID/status
		if (fd == NULL) 
			return -1;

		if (fgets(buffer_file, sizeof(buffer_file), fd) == NULL) {
      			fclose(fd);
			return -1;
		}

		if (sscanf(buffer_file, "Name: %200s\n", name) != 1) {
	      		fclose(fd);
			return -1;
		}
		fclose(fd);
	
	} 

	snprintf(connection->program_name, sizeof(connection->program_name), "%s/%s", pid, name);
	return 0;
}

struct connection_entry * find_connection(struct connection_table * table_connection, __u32 inode)
{
	__u32 i;
	for( i = 0 ; i < table_connection->entries ; i++) {
		if (table_connection->table[i].inode == inode)
			return &table_connection->table[i];
	}
	return NULL;
}

DWORD linux_proc_fill_program_name(struct connection_table * table_connection)
{
	char buffer[60];
	struct dirent *procent, *fdent;
	DIR * procfd, * pidfd;
	struct stat stat_buf;
	struct connection_entry * connection;

	procfd = opendir("/proc");
	if (procfd == NULL)
		return -1;
	while ((procent = readdir(procfd)) != NULL) {
		// not a pid directory
		if (!isdigit(*(procent->d_name)))
			continue;

		snprintf(buffer, sizeof(buffer), "/proc/%s/fd/", procent->d_name);
		if ((pidfd = opendir(buffer)) == NULL)
			continue;

		while((fdent = readdir(pidfd)) != NULL) {

			snprintf(buffer, sizeof(buffer), "/proc/%s/fd/%s", procent->d_name, fdent->d_name);
			if (stat(buffer, &stat_buf) < 0)
            			continue;
			if (!S_ISSOCK(stat_buf.st_mode))
				continue;
			// ok, FD is a socket, search if we have it in our list
			if ((connection = find_connection(table_connection, stat_buf.st_ino)) != NULL)
				linux_proc_get_program_name(connection, procent->d_name);
		}
		closedir(pidfd);
	}
	closedir(procfd);
	return 0;
}


DWORD linux_proc_get_connection_table(struct connection_table ** table_connection)
{
	*table_connection = calloc(sizeof(struct connection_table) + 10 * sizeof(struct connection_entry), 1);
	(*table_connection)->max_entries = 10;

	linux_parse_proc_net_file("/proc/net/tcp" , table_connection, AF_INET , "tcp",  0);
	linux_parse_proc_net_file("/proc/net/tcp6", table_connection, AF_INET6, "tcp6", 0);
	linux_parse_proc_net_file("/proc/net/udp" , table_connection, AF_INET , "udp",  1);
	linux_parse_proc_net_file("/proc/net/udp6", table_connection, AF_INET6, "udp6", 1);

	// fill the PID/program_name part
	linux_proc_fill_program_name(*table_connection);

	return ERROR_SUCCESS;
}

DWORD linux_get_connection_table(Remote *remote, Packet *response)
{
	struct connection_table *table_connection = NULL;
	__u32 local_port_be, remote_port_be, uid_be, inode_be;
	__u32 index;
	DWORD result;

	dprintf("getting connection list through /proc/net");
	result = linux_proc_get_connection_table(&table_connection);
	dprintf("result = %d, table_connection = 0x%p , entries : %d", result, table_connection, table_connection->entries);

	for(index = 0; index < table_connection->entries; index++) {
		Tlv connection[9];
		if (table_connection->table[index].type == AF_INET) {
			connection[0].header.type      = TLV_TYPE_LOCAL_HOST_RAW;
			connection[0].header.length    = sizeof(__u32);
			connection[0].buffer           = (PUCHAR)&table_connection->table[index].local_addr.addr;

			connection[1].header.type      = TLV_TYPE_PEER_HOST_RAW;
			connection[1].header.length    = sizeof(__u32);
			connection[1].buffer           = (PUCHAR)&table_connection->table[index].remote_addr.addr;
		}
		else {
			connection[0].header.type      = TLV_TYPE_LOCAL_HOST_RAW;
			connection[0].header.length    = sizeof(__u128);
			connection[0].buffer           = (PUCHAR)&table_connection->table[index].local_addr.addr6;

			connection[1].header.type      = TLV_TYPE_PEER_HOST_RAW;
			connection[1].header.length    = sizeof(__u128);
			connection[1].buffer           = (PUCHAR)&table_connection->table[index].remote_addr.addr6;
		}

		local_port_be = htonl(table_connection->table[index].local_port & 0x0000ffff);
		connection[2].header.type      = TLV_TYPE_LOCAL_PORT;
		connection[2].header.length    = sizeof(__u32);
		connection[2].buffer           = (PUCHAR)&local_port_be;

		remote_port_be = htonl(table_connection->table[index].remote_port & 0x0000ffff);
		connection[3].header.type      = TLV_TYPE_PEER_PORT;
		connection[3].header.length    = sizeof(__u32);
		connection[3].buffer           = (PUCHAR)&remote_port_be;

		connection[4].header.type      = TLV_TYPE_MAC_NAME;
		connection[4].header.length    = strlen(table_connection->table[index].protocol) + 1;
		connection[4].buffer           = (PUCHAR)(table_connection->table[index].protocol);

		connection[5].header.type      = TLV_TYPE_SUBNET_STRING;
		connection[5].header.length    = strlen(table_connection->table[index].state) + 1;
		connection[5].buffer           = (PUCHAR)(table_connection->table[index].state);

		uid_be = htonl(table_connection->table[index].uid);
		connection[6].header.type      = TLV_TYPE_PID;
		connection[6].header.length    = sizeof(__u32);
		connection[6].buffer           = (PUCHAR)&uid_be;

		inode_be = htonl(table_connection->table[index].inode);
		connection[7].header.type      = TLV_TYPE_ROUTE_METRIC;
		connection[7].header.length    = sizeof(__u32);
		connection[7].buffer           = (PUCHAR)&inode_be;

		connection[8].header.type      = TLV_TYPE_PROCESS_NAME;
		connection[8].header.length    = strlen(table_connection->table[index].program_name) + 1;
		connection[8].buffer           = (PUCHAR)(table_connection->table[index].program_name);

		packet_add_tlv_group(response, TLV_TYPE_NETSTAT_ENTRY, connection, 9);
	}
	dprintf("sent %d connections", table_connection->entries);

	if (table_connection)
		free(table_connection);

}

#endif

/*
 * Returns zero or more connection entries to the requestor from the connection list
 */
DWORD request_net_config_get_netstat(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result;

#ifdef _WIN32
	result = windows_get_connection_table(remote, response);
#else
	result = linux_get_connection_table(remote, response);
#endif

	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

