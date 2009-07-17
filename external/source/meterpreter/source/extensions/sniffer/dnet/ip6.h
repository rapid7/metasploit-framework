/*
 * ip6.h
 *
 * Internet Protocol, Version 6 (RFC 2460).
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: ip6.h,v 1.6 2004/02/23 10:01:15 dugsong Exp $
 */

#ifndef DNET_IP6_H
#define DNET_IP6_H

#define IP6_ADDR_LEN	16
#define IP6_ADDR_BITS	128

#define IP6_HDR_LEN	40		/* IPv6 header length */
#define IP6_LEN_MIN	IP6_HDR_LEN
#define IP6_LEN_MAX	65535		/* non-jumbo payload */

#define IP6_MTU_MIN	1280		/* minimum MTU (1024 + 256) */

typedef struct ip6_addr {
	uint8_t         data[IP6_ADDR_LEN];
} ip6_addr_t;

#ifndef __GNUC__
# define __attribute__(x)
# pragma pack(1)
#endif

/*
 * IPv6 header
 */
struct ip6_hdr {
	union {
		struct ip6_hdr_ctl {
			uint32_t	ip6_un1_flow; /* 20 bits of flow ID */
			uint16_t	ip6_un1_plen; /* payload length */
			uint8_t		ip6_un1_nxt;  /* next header */
			uint8_t		ip6_un1_hlim; /* hop limit */
		} ip6_un1;
		uint8_t	ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
	} ip6_ctlun;
	ip6_addr_t	ip6_src;
	ip6_addr_t	ip6_dst;
} __attribute__((__packed__));

#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt	/* IP_PROTO_* */
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim

#define IP6_VERSION		0x60
#define IP6_VERSION_MASK	0xf0		/* ip6_vfc version */

#if DNET_BYTESEX == DNET_BIG_ENDIAN
#define IP6_FLOWINFO_MASK	0x0fffffff	/* ip6_flow info (28 bits) */
#define IP6_FLOWLABEL_MASK	0x000fffff	/* ip6_flow label (20 bits) */
#elif DNET_BYTESEX == DNET_LIL_ENDIAN
#define IP6_FLOWINFO_MASK	0xffffff0f	/* ip6_flow info (28 bits) */
#define IP6_FLOWLABEL_MASK	0xffff0f00	/* ip6_flow label (20 bits) */
#endif

/*
 * Hop limit (ip6_hlim)
 */
#define IP6_HLIM_DEFAULT	64
#define IP6_HLIM_MAX		255

/*
 * Preferred extension header order from RFC 2460, 4.1:
 *
 * IP_PROTO_IPV6, IP_PROTO_HOPOPTS, IP_PROTO_DSTOPTS, IP_PROTO_ROUTING,
 * IP_PROTO_FRAGMENT, IP_PROTO_AH, IP_PROTO_ESP, IP_PROTO_DSTOPTS, IP_PROTO_*
 */

/*
 * Routing header data (IP_PROTO_ROUTING)
 */
struct ip6_ext_data_routing {
	uint8_t  type;			/* routing type */
	uint8_t  segleft;		/* segments left */
	/* followed by routing type specific data */
} __attribute__((__packed__));

struct ip6_ext_data_routing0 {
	uint8_t  type;			/* always zero */
	uint8_t  segleft;		/* segments left */
	uint8_t  reserved;		/* reserved field */
	uint8_t  slmap[3];		/* strict/loose bit map */
	ip6_addr_t  addr[1];		/* up to 23 addresses */
} __attribute__((__packed__));

/*
 * Fragment header data (IP_PROTO_FRAGMENT)
 */
struct ip6_ext_data_fragment {
	uint16_t  offlg;		/* offset, reserved, and flag */
	uint32_t  ident;		/* identification */
} __attribute__((__packed__));

/*
 * Fragmentation offset, reserved, and flags (offlg)
 */
#if DNET_BYTESEX == DNET_BIG_ENDIAN
#define IP6_OFF_MASK		0xfff8	/* mask out offset from offlg */
#define IP6_RESERVED_MASK	0x0006	/* reserved bits in offlg */
#define IP6_MORE_FRAG		0x0001	/* more-fragments flag */
#elif DNET_BYTESEX == DNET_LIL_ENDIAN
#define IP6_OFF_MASK		0xf8ff	/* mask out offset from offlg */
#define IP6_RESERVED_MASK	0x0600	/* reserved bits in offlg */
#define IP6_MORE_FRAG		0x0100	/* more-fragments flag */
#endif

/*
 * Option types, for IP_PROTO_HOPOPTS, IP_PROTO_DSTOPTS headers
 */
#define IP6_OPT_PAD1		0x00	/* 00 0 00000 */
#define IP6_OPT_PADN		0x01	/* 00 0 00001 */
#define IP6_OPT_JUMBO		0xC2	/* 11 0 00010 = 194 */
#define IP6_OPT_JUMBO_LEN	6
#define IP6_OPT_RTALERT		0x05	/* 00 0 00101 */
#define IP6_OPT_RTALERT_LEN	4
#define IP6_OPT_RTALERT_MLD	0	/* Datagram contains an MLD message */
#define IP6_OPT_RTALERT_RSVP	1	/* Datagram contains an RSVP message */
#define IP6_OPT_RTALERT_ACTNET	2 	/* contains an Active Networks msg */
#define IP6_OPT_LEN_MIN		2

#define IP6_OPT_TYPE(o)		((o) & 0xC0)	/* high 2 bits of opt_type */
#define IP6_OPT_TYPE_SKIP	0x00	/* continue processing on failure */
#define IP6_OPT_TYPE_DISCARD	0x40	/* discard packet on failure */
#define IP6_OPT_TYPE_FORCEICMP	0x80	/* discard and send ICMP on failure */
#define IP6_OPT_TYPE_ICMP	0xC0	/* ...only if non-multicast dst */

#define IP6_OPT_MUTABLE		0x20	/* option data may change en route */

/*
 * Extension header (chained via {ip6,ext}_nxt, following IPv6 header)
 */
struct ip6_ext_hdr {
	uint8_t  ext_nxt;	/* next header */
	uint8_t  ext_len;	/* following length in units of 8 octets */
	union {
		struct ip6_ext_data_routing	routing;
		struct ip6_ext_data_fragment	fragment;
	} ext_data;
} __attribute__((__packed__));

#ifndef __GNUC__
# pragma pack()
#endif

/*
 * Reserved addresses
 */
#define IP6_ADDR_UNSPEC	\
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define IP6_ADDR_LOOPBACK \
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

#define ip6_pack_hdr(hdr, fc, fl, plen, nxt, hlim, src, dst) do {	\
	struct ip6_hdr *ip6 = (struct ip6_hdr *)(hdr);			\
	ip6->ip6_flow = htonl(((uint32_t)(fc) << 28) &			\
	    (IP6_FLOWLABEL_MASK | (fl)));				\
	ip6->ip6_vfc = (IP6_VERSION | ((fc) >> 4));			\
	ip6->ip6_plen = htons((plen));					\
	ip6->ip6_nxt = (nxt); ip6->ip6_hlim = (hlim);			\
	memmove(&ip6->ip6_src, &(src), IP6_ADDR_LEN);			\
	memmove(&ip6->ip6_dst, &(dst), IP6_ADDR_LEN);			\
} while (0);

__BEGIN_DECLS
char	*ip6_ntop(const ip6_addr_t *ip6, char *dst, size_t size);
int	 ip6_pton(const char *src, ip6_addr_t *dst);
char	*ip6_ntoa(const ip6_addr_t *ip6);
#define	 ip6_aton ip6_pton

void	 ip6_checksum(void *buf, size_t len);
__END_DECLS

#endif /* DNET_IP6_H */
