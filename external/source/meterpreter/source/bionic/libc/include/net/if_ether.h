/*	$NetBSD: if_ether.h,v 1.43 2006/11/24 01:04:30 rpaulo Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if_ether.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NET_IF_ETHER_H_
#define _NET_IF_ETHER_H_

#include <sys/types.h>

#ifdef _KERNEL
#ifdef _KERNEL_OPT
#include "opt_mbuftrace.h"
#endif
#include <sys/mbuf.h>
#endif

/*
 * Some basic Ethernet constants.
 */
#define	ETHER_ADDR_LEN	6	/* length of an Ethernet address */
#define	ETHER_TYPE_LEN	2	/* length of the Ethernet type field */
#define	ETHER_CRC_LEN	4	/* length of the Ethernet CRC */
#define	ETHER_HDR_LEN	((ETHER_ADDR_LEN * 2) + ETHER_TYPE_LEN)
#define	ETHER_MIN_LEN	64	/* minimum frame length, including CRC */
#define	ETHER_MAX_LEN	1518	/* maximum frame length, including CRC */
#define	ETHER_MAX_LEN_JUMBO 9018 /* maximum jumbo frame len, including CRC */

/*
 * Some Ethernet extensions.
 */
#define	ETHER_VLAN_ENCAP_LEN 4	/* length of 802.1Q VLAN encapsulation */

/*
 * Ethernet address - 6 octets
 * this is only used by the ethers(3) functions.
 */
struct ether_addr {
	u_int8_t ether_addr_octet[ETHER_ADDR_LEN];
} __attribute__((__packed__));

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct	ether_header {
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];
	u_int8_t  ether_shost[ETHER_ADDR_LEN];
	u_int16_t ether_type;
} __attribute__((__packed__));

#include <net/ethertypes.h>

#define	ETHER_IS_MULTICAST(addr) (*(addr) & 0x01) /* is address mcast/bcast? */

#define	ETHERMTU_JUMBO	(ETHER_MAX_LEN_JUMBO - ETHER_HDR_LEN - ETHER_CRC_LEN)
#define	ETHERMTU	(ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)
#define	ETHERMIN	(ETHER_MIN_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)

/*
 * Compute the maximum frame size based on ethertype (i.e. possible
 * encapsulation) and whether or not an FCS is present.
 */
#define	ETHER_MAX_FRAME(ifp, etype, hasfcs)				\
	((ifp)->if_mtu + ETHER_HDR_LEN +				\
	 ((hasfcs) ? ETHER_CRC_LEN : 0) +				\
	 (((etype) == ETHERTYPE_VLAN) ? ETHER_VLAN_ENCAP_LEN : 0))

/*
 * Ethernet CRC32 polynomials (big- and little-endian verions).
 */
#define	ETHER_CRC_POLY_LE	0xedb88320
#define	ETHER_CRC_POLY_BE	0x04c11db6

#ifndef _STANDALONE

/*
 * Ethernet-specific mbuf flags.
 */
#define	M_HASFCS	M_LINK0	/* FCS included at end of frame */
#define	M_PROMISC	M_LINK1	/* this packet is not for us */

#ifdef _KERNEL
/*
 * Macro to map an IP multicast address to an Ethernet multicast address.
 * The high-order 25 bits of the Ethernet address are statically assigned,
 * and the low-order 23 bits are taken from the low end of the IP address.
 */
#define ETHER_MAP_IP_MULTICAST(ipaddr, enaddr)				\
	/* struct in_addr *ipaddr; */					\
	/* u_int8_t enaddr[ETHER_ADDR_LEN]; */				\
{									\
	(enaddr)[0] = 0x01;						\
	(enaddr)[1] = 0x00;						\
	(enaddr)[2] = 0x5e;						\
	(enaddr)[3] = ((u_int8_t *)ipaddr)[1] & 0x7f;			\
	(enaddr)[4] = ((u_int8_t *)ipaddr)[2];				\
	(enaddr)[5] = ((u_int8_t *)ipaddr)[3];				\
}
/*
 * Macro to map an IP6 multicast address to an Ethernet multicast address.
 * The high-order 16 bits of the Ethernet address are statically assigned,
 * and the low-order 32 bits are taken from the low end of the IP6 address.
 */
#define ETHER_MAP_IPV6_MULTICAST(ip6addr, enaddr)			\
	/* struct in6_addr *ip6addr; */					\
	/* u_int8_t enaddr[ETHER_ADDR_LEN]; */				\
{                                                                       \
	(enaddr)[0] = 0x33;						\
	(enaddr)[1] = 0x33;						\
	(enaddr)[2] = ((u_int8_t *)ip6addr)[12];			\
	(enaddr)[3] = ((u_int8_t *)ip6addr)[13];			\
	(enaddr)[4] = ((u_int8_t *)ip6addr)[14];			\
	(enaddr)[5] = ((u_int8_t *)ip6addr)[15];			\
}
#endif

#define	ETHERCAP_VLAN_MTU	0x00000001	/* VLAN-compatible MTU */
#define	ETHERCAP_VLAN_HWTAGGING	0x00000002	/* hardware VLAN tag support */
#define	ETHERCAP_JUMBO_MTU	0x00000004	/* 9000 byte MTU supported */

#ifdef	_KERNEL
extern const uint8_t etherbroadcastaddr[ETHER_ADDR_LEN];
extern const uint8_t ethermulticastaddr_slowprotocols[ETHER_ADDR_LEN];
extern const uint8_t ether_ipmulticast_min[ETHER_ADDR_LEN];
extern const uint8_t ether_ipmulticast_max[ETHER_ADDR_LEN];

int	ether_ioctl(struct ifnet *, u_long, caddr_t);
int	ether_addmulti (struct ifreq *, struct ethercom *);
int	ether_delmulti (struct ifreq *, struct ethercom *);
int	ether_changeaddr (struct ifreq *, struct ethercom *);
int	ether_multiaddr(struct sockaddr *, u_int8_t[], u_int8_t[]);

/*
 * Ethernet 802.1Q VLAN structures.
 */

/* add VLAN tag to input/received packet */
#define	VLAN_INPUT_TAG(ifp, m, vlanid, _errcase)	\
	do {								\
                struct m_tag *mtag =					\
                    m_tag_get(PACKET_TAG_VLAN, sizeof(u_int), M_NOWAIT);\
                if (mtag == NULL) {					\
			ifp->if_ierrors++;				\
                        printf("%s: unable to allocate VLAN tag\n",	\
                            ifp->if_xname);				\
                        m_freem(m);					\
                        _errcase;					\
                }							\
                *(u_int *)(mtag + 1) = vlanid;				\
                m_tag_prepend(m, mtag);					\
	} while(0)

/* extract VLAN tag from output/trasmit packet */
#define VLAN_OUTPUT_TAG(ec, m0)			\
	VLAN_ATTACHED(ec) ? m_tag_find((m0), PACKET_TAG_VLAN, NULL) : NULL

/* extract VLAN ID value from a VLAN tag */
#define VLAN_TAG_VALUE(mtag)	\
	((*(u_int *)(mtag + 1)) & 4095)

/* test if any VLAN is configured for this interface */
#define VLAN_ATTACHED(ec)	((ec)->ec_nvlans > 0)

void	ether_ifattach(struct ifnet *, const u_int8_t *);
void	ether_ifdetach(struct ifnet *);

char	*ether_sprintf(const u_int8_t *);
char	*ether_snprintf(char *, size_t, const u_int8_t *);

u_int32_t ether_crc32_le(const u_int8_t *, size_t);
u_int32_t ether_crc32_be(const u_int8_t *, size_t);

int	ether_nonstatic_aton(u_char *, char *);
#else
/*
 * Prototype ethers(3) functions.
 */
#include <sys/cdefs.h>
__BEGIN_DECLS
char *	ether_ntoa __P((const struct ether_addr *));
struct ether_addr *
	ether_aton __P((const char *));
int	ether_ntohost __P((char *, const struct ether_addr *));
int	ether_hostton __P((const char *, struct ether_addr *));
int	ether_line __P((const char *, struct ether_addr *, char *));
__END_DECLS
#endif

#endif /* _STANDALONE */

#endif /* !_NET_IF_ETHER_H_ */
