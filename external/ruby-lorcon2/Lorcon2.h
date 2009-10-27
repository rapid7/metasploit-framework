#ifndef _MSFLORCON_H
#define _MSFLORCON_H

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>

#include <lorcon2/lorcon.h>
#include <pcap.h>

struct rldev {
	struct lorcon *context;
};

struct rlpack {
	struct lorcon_packet *packet;

	/* dot3 construction via multiple elements */
	u_char *bssid, *dot3;
	int dir, len;
};


typedef struct rblorconjob {
	struct pcap_pkthdr hdr;
    unsigned char *pkt;
} rblorconjob_t;

#endif
