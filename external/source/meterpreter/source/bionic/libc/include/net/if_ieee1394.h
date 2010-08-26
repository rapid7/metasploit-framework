/*	$NetBSD: if_ieee1394.h,v 1.6 2005/12/10 23:21:38 elad Exp $	*/

/*
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Atsushi Onoe.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _NET_IF_IEEE1394_H_
#define _NET_IF_IEEE1394_H_

/* hardware address information for arp / nd */
struct ieee1394_hwaddr {
	u_int8_t	iha_uid[8];		/* node unique ID */
	u_int8_t	iha_maxrec;		/* max_rec in the config ROM */
	u_int8_t	iha_speed;		/* min of link/PHY speed */
	u_int8_t	iha_offset[6];		/* unicast FIFO address */
};

/*
 * BPF wants to see one of these.
 */
struct ieee1394_bpfhdr {
	uint8_t		ibh_dhost[8];
	uint8_t		ibh_shost[8];
	uint16_t	ibh_type;
};

#ifdef _KERNEL

/* pseudo header */
struct ieee1394_header {
	u_int8_t	ih_uid[8];		/* dst/src uid */
	u_int8_t	ih_maxrec;		/* dst maxrec for tx */
	u_int8_t	ih_speed;		/* speed */
	u_int8_t	ih_offset[6];		/* dst offset */
};

/* unfragment encapsulation header */
struct ieee1394_unfraghdr {
	u_int16_t	iuh_ft;			/* fragment type == 0 */
	u_int16_t	iuh_etype;		/* ether_type */
};

/* fragmented encapsulation header */
struct ieee1394_fraghdr {
	u_int16_t	ifh_ft_size;		/* fragment type, data size-1 */
	u_int16_t	ifh_etype_off;		/* etype for first fragment */
						/* offset for subseq frag */
	u_int16_t	ifh_dgl;		/* datagram label */
	u_int16_t	ifh_reserved;
};

#define	IEEE1394_FT_SUBSEQ	0x8000
#define	IEEE1394_FT_MORE	0x4000

#define	IEEE1394MTU		1500

#define	IEEE1394_GASP_LEN	8		/* GASP header for Stream */
#define	IEEE1394_ADDR_LEN	8
#define	IEEE1394_CRC_LEN	4

struct ieee1394_reass_pkt {
	LIST_ENTRY(ieee1394_reass_pkt) rp_next;
	struct mbuf	*rp_m;
	u_int16_t	rp_size;
	u_int16_t	rp_etype;
	u_int16_t	rp_off;
	u_int16_t	rp_dgl;
	u_int16_t	rp_len;
	u_int16_t	rp_ttl;
};

struct ieee1394_reassq {
	LIST_ENTRY(ieee1394_reassq) rq_node;
	LIST_HEAD(, ieee1394_reass_pkt) rq_pkt;
	u_int32_t	fr_id;
};

struct ieee1394com {
	struct ifnet	fc_if;
	struct ieee1394_hwaddr ic_hwaddr;
	u_int16_t	ic_dgl;
	LIST_HEAD(, ieee1394_reassq) ic_reassq;
};

const char *ieee1394_sprintf(const u_int8_t *);
void ieee1394_input(struct ifnet *, struct mbuf *, u_int16_t);
void ieee1394_ifattach(struct ifnet *, const struct ieee1394_hwaddr *);
void ieee1394_ifdetach(struct ifnet *);
int  ieee1394_ioctl(struct ifnet *, u_long, caddr_t);
struct mbuf * ieee1394_fragment(struct ifnet *, struct mbuf *, int, u_int16_t);
void ieee1394_drain(struct ifnet *);
void ieee1394_watchdog(struct ifnet *);
#endif /* _KERNEL */

#endif /* !_NET_IF_IEEE1394_H_ */
