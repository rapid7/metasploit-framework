/*
 * udp.h
 *
 * User Datagram Protocol (RFC 768).
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: udp.h,v 1.8 2002/04/02 05:05:39 dugsong Exp $
 */

#ifndef DNET_UDP_H
#define DNET_UDP_H

#define UDP_HDR_LEN	8

struct udp_hdr {
	uint16_t	uh_sport;	/* source port */
	uint16_t	uh_dport;	/* destination port */
	uint16_t	uh_ulen;	/* udp length (including header) */
	uint16_t	uh_sum;		/* udp checksum */
};

#define UDP_PORT_MAX	65535

#define udp_pack_hdr(hdr, sport, dport, ulen) do {		\
	struct udp_hdr *udp_pack_p = (struct udp_hdr *)(hdr);	\
	udp_pack_p->uh_sport = htons(sport);			\
	udp_pack_p->uh_dport = htons(dport);			\
	udp_pack_p->uh_ulen = htons(ulen);			\
} while (0)

#endif /* DNET_UDP_H */
