/*
 * icmp.h
 *
 * Internet Control Message Protocol.
 * RFC 792, 950, 1256, 1393, 1475, 2002, 2521
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: icmp.h,v 1.14 2003/03/16 17:39:17 dugsong Exp $
 */

#ifndef DNET_ICMP_H
#define DNET_ICMP_H

#define ICMP_HDR_LEN	4	/* base ICMP header length */
#define ICMP_LEN_MIN	8	/* minimum ICMP message size, with header */

#ifndef __GNUC__
# define __attribute__(x)
# pragma pack(1)
#endif

/*
 * ICMP header
 */
struct icmp_hdr {
	uint8_t		icmp_type;	/* type of message, see below */
	uint8_t		icmp_code;	/* type sub code */
	uint16_t	icmp_cksum;	/* ones complement cksum of struct */
};

/*
 * Types (icmp_type) and codes (icmp_code) -
 * http://www.iana.org/assignments/icmp-parameters
 */
#define		ICMP_CODE_NONE		0	/* for types without codes */
#define	ICMP_ECHOREPLY		0		/* echo reply */
#define	ICMP_UNREACH		3		/* dest unreachable, codes: */
#define		ICMP_UNREACH_NET		0	/* bad net */
#define		ICMP_UNREACH_HOST		1	/* bad host */
#define		ICMP_UNREACH_PROTO		2	/* bad protocol */
#define		ICMP_UNREACH_PORT		3	/* bad port */
#define		ICMP_UNREACH_NEEDFRAG		4	/* IP_DF caused drop */
#define		ICMP_UNREACH_SRCFAIL		5	/* src route failed */
#define		ICMP_UNREACH_NET_UNKNOWN	6	/* unknown net */
#define		ICMP_UNREACH_HOST_UNKNOWN	7	/* unknown host */
#define		ICMP_UNREACH_ISOLATED		8	/* src host isolated */
#define		ICMP_UNREACH_NET_PROHIB		9	/* for crypto devs */
#define		ICMP_UNREACH_HOST_PROHIB	10	/* ditto */
#define		ICMP_UNREACH_TOSNET		11	/* bad tos for net */
#define		ICMP_UNREACH_TOSHOST		12	/* bad tos for host */
#define		ICMP_UNREACH_FILTER_PROHIB	13	/* prohibited access */
#define		ICMP_UNREACH_HOST_PRECEDENCE	14	/* precedence error */
#define		ICMP_UNREACH_PRECEDENCE_CUTOFF	15	/* precedence cutoff */
#define	ICMP_SRCQUENCH		4		/* packet lost, slow down */
#define	ICMP_REDIRECT		5		/* shorter route, codes: */
#define		ICMP_REDIRECT_NET		0	/* for network */
#define		ICMP_REDIRECT_HOST		1	/* for host */
#define		ICMP_REDIRECT_TOSNET		2	/* for tos and net */
#define		ICMP_REDIRECT_TOSHOST		3	/* for tos and host */
#define	ICMP_ALTHOSTADDR	6		/* alternate host address */
#define	ICMP_ECHO		8		/* echo service */
#define	ICMP_RTRADVERT		9		/* router advertise, codes: */
#define		ICMP_RTRADVERT_NORMAL		0	/* normal */
#define		ICMP_RTRADVERT_NOROUTE_COMMON 16	/* selective routing */
#define	ICMP_RTRSOLICIT		10		/* router solicitation */
#define	ICMP_TIMEXCEED		11		/* time exceeded, code: */
#define		ICMP_TIMEXCEED_INTRANS		0	/* ttl==0 in transit */
#define		ICMP_TIMEXCEED_REASS		1	/* ttl==0 in reass */
#define	ICMP_PARAMPROB		12		/* ip header bad */
#define		ICMP_PARAMPROB_ERRATPTR		0	/* req. opt. absent */
#define		ICMP_PARAMPROB_OPTABSENT	1	/* req. opt. absent */
#define		ICMP_PARAMPROB_LENGTH		2	/* bad length */
#define	ICMP_TSTAMP		13		/* timestamp request */
#define	ICMP_TSTAMPREPLY	14		/* timestamp reply */
#define	ICMP_INFO		15		/* information request */
#define	ICMP_INFOREPLY		16		/* information reply */
#define	ICMP_MASK		17		/* address mask request */
#define	ICMP_MASKREPLY		18		/* address mask reply */
#define ICMP_TRACEROUTE		30		/* traceroute */
#define ICMP_DATACONVERR	31		/* data conversion error */
#define ICMP_MOBILE_REDIRECT	32		/* mobile host redirect */
#define ICMP_IPV6_WHEREAREYOU	33		/* IPv6 where-are-you */
#define ICMP_IPV6_IAMHERE	34		/* IPv6 i-am-here */
#define ICMP_MOBILE_REG		35		/* mobile registration req */
#define ICMP_MOBILE_REGREPLY	36		/* mobile registration reply */
#define ICMP_DNS		37		/* domain name request */
#define ICMP_DNSREPLY		38		/* domain name reply */
#define ICMP_SKIP		39		/* SKIP */
#define ICMP_PHOTURIS		40		/* Photuris */
#define		ICMP_PHOTURIS_UNKNOWN_INDEX	0	/* unknown sec index */
#define		ICMP_PHOTURIS_AUTH_FAILED	1	/* auth failed */
#define		ICMP_PHOTURIS_DECOMPRESS_FAILED	2	/* decompress failed */
#define		ICMP_PHOTURIS_DECRYPT_FAILED	3	/* decrypt failed */
#define		ICMP_PHOTURIS_NEED_AUTHN	4	/* no authentication */
#define		ICMP_PHOTURIS_NEED_AUTHZ	5	/* no authorization */
#define	ICMP_TYPE_MAX		40

#define	ICMP_INFOTYPE(type)						\
	((type) == ICMP_ECHOREPLY || (type) == ICMP_ECHO ||		\
	(type) == ICMP_RTRADVERT || (type) == ICMP_RTRSOLICIT ||	\
	(type) == ICMP_TSTAMP || (type) == ICMP_TSTAMPREPLY ||		\
	(type) == ICMP_INFO || (type) == ICMP_INFOREPLY ||		\
	(type) == ICMP_MASK || (type) == ICMP_MASKREPLY)

/*
 * Echo message data
 */
struct icmp_msg_echo {
	uint16_t	icmp_id;
	uint16_t	icmp_seq;
	uint8_t		icmp_data __flexarr;	/* optional data */
};

/*
 * Fragmentation-needed (unreachable) message data
 */
struct icmp_msg_needfrag {
	uint16_t	icmp_void;		/* must be zero */
	uint16_t	icmp_mtu;		/* MTU of next-hop network */
	uint8_t		icmp_ip __flexarr;	/* IP hdr + 8 bytes of pkt */
};

/*
 *  Unreachable, source quench, redirect, time exceeded,
 *  parameter problem message data
 */
struct icmp_msg_quote {
	uint32_t	icmp_void;		/* must be zero */
#define icmp_gwaddr	icmp_void		/* router IP address to use */
#define icmp_pptr	icmp_void		/* ptr to bad octet field */
	uint8_t		icmp_ip __flexarr;	/* IP hdr + 8 bytes of pkt */
};

/*
 * Router advertisement message data, RFC 1256
 */
struct icmp_msg_rtradvert {
	uint8_t		icmp_num_addrs;		/* # of address / pref pairs */
	uint8_t		icmp_wpa;		/* words / address == 2 */
	uint16_t	icmp_lifetime;		/* route lifetime in seconds */
	struct icmp_msg_rtr_data {
		uint32_t	icmp_void;
#define icmp_gwaddr		icmp_void	/* router IP address */
		uint32_t	icmp_pref;	/* router preference (usu 0) */
	} icmp_rtr __flexarr;			/* variable # of routers */
};
#define ICMP_RTR_PREF_NODEFAULT	0x80000000	/* do not use as default gw */

/*
 * Timestamp message data
 */
struct icmp_msg_tstamp {
	uint32_t	icmp_id;		/* identifier */
	uint32_t	icmp_seq;		/* sequence number */
	uint32_t	icmp_ts_orig;		/* originate timestamp */
	uint32_t	icmp_ts_rx;		/* receive timestamp */
	uint32_t	icmp_ts_tx;		/* transmit timestamp */
};

/*
 * Address mask message data, RFC 950
 */
struct icmp_msg_mask {
	uint32_t	icmp_id;		/* identifier */
	uint32_t	icmp_seq;		/* sequence number */
	uint32_t	icmp_mask;		/* address mask */
};

/*
 * Traceroute message data, RFC 1393, RFC 1812
 */
struct icmp_msg_traceroute {
	uint16_t	icmp_id;		/* identifier */
	uint16_t	icmp_void;		/* unused */
	uint16_t	icmp_ohc;		/* outbound hop count */
	uint16_t	icmp_rhc;		/* return hop count */
	uint32_t	icmp_speed;		/* link speed, bytes/sec */
	uint32_t	icmp_mtu;		/* MTU in bytes */
};

/*
 * Domain name reply message data, RFC 1788
 */
struct icmp_msg_dnsreply {
	uint16_t	icmp_id;		/* identifier */
	uint16_t	icmp_seq;		/* sequence number */
	uint32_t	icmp_ttl;		/* time-to-live */
	uint8_t		icmp_names __flexarr;	/* variable number of names */
};

/*
 * Generic identifier, sequence number data
 */
struct icmp_msg_idseq {
	uint16_t	icmp_id;
	uint16_t	icmp_seq;
};

/*
 * ICMP message union
 */
union icmp_msg {
	struct icmp_msg_echo	   echo;	/* ICMP_ECHO{REPLY} */
	struct icmp_msg_quote	   unreach;	/* ICMP_UNREACH */
	struct icmp_msg_needfrag   needfrag;	/* ICMP_UNREACH_NEEDFRAG */
	struct icmp_msg_quote	   srcquench;	/* ICMP_SRCQUENCH */
	struct icmp_msg_quote	   redirect;	/* ICMP_REDIRECT (set to 0) */
	uint32_t		   rtrsolicit;	/* ICMP_RTRSOLICIT */
	struct icmp_msg_rtradvert  rtradvert;	/* ICMP_RTRADVERT */
	struct icmp_msg_quote	   timexceed;	/* ICMP_TIMEXCEED */
	struct icmp_msg_quote	   paramprob;	/* ICMP_PARAMPROB */
	struct icmp_msg_tstamp	   tstamp;	/* ICMP_TSTAMP{REPLY} */
	struct icmp_msg_idseq	   info;	/* ICMP_INFO{REPLY} */
	struct icmp_msg_mask	   mask;	/* ICMP_MASK{REPLY} */
	struct icmp_msg_traceroute traceroute;	/* ICMP_TRACEROUTE */
	struct icmp_msg_idseq	   dns;		/* ICMP_DNS */
	struct icmp_msg_dnsreply   dnsreply;	/* ICMP_DNSREPLY */
};

#ifndef __GNUC__
# pragma pack()
#endif

#define icmp_pack_hdr(hdr, type, code) do {				\
	struct icmp_hdr *icmp_pack_p = (struct icmp_hdr *)(hdr);	\
	icmp_pack_p->icmp_type = type; icmp_pack_p->icmp_code = code;	\
} while (0)

#define icmp_pack_hdr_echo(hdr, type, code, id, seq, data, len) do {	\
	struct icmp_msg_echo *echo_pack_p = (struct icmp_msg_echo *)	\
		((uint8_t *)(hdr) + ICMP_HDR_LEN);			\
	icmp_pack_hdr(hdr, type, code);					\
	echo_pack_p->icmp_id = htons(id);				\
	echo_pack_p->icmp_seq = htons(seq);				\
	memmove(echo_pack_p->icmp_data, data, len);			\
} while (0)

#define icmp_pack_hdr_quote(hdr, type, code, word, pkt, len) do {	\
	struct icmp_msg_quote *quote_pack_p = (struct icmp_msg_quote *)	\
		((uint8_t *)(hdr) + ICMP_HDR_LEN);			\
	icmp_pack_hdr(hdr, type, code);					\
	quote_pack_p->icmp_void = htonl(word);				\
	memmove(quote_pack_p->icmp_ip, pkt, len);			\
} while (0)

#define icmp_pack_hdr_mask(hdr, type, code, id, seq, mask) do {		\
	struct icmp_msg_mask *mask_pack_p = (struct icmp_msg_mask *)	\
		((uint8_t *)(hdr) + ICMP_HDR_LEN);			\
	icmp_pack_hdr(hdr, type, code);					\
	mask_pack_p->icmp_id = htons(id);				\
	mask_pack_p->icmp_seq = htons(seq);				\
	mask_pack_p->icmp_mask = htonl(mask);				\
} while (0)

#define icmp_pack_hdr_needfrag(hdr, type, code, mtu, pkt, len) do {	\
	struct icmp_msg_needfrag *frag_pack_p =				\
	(struct icmp_msg_needfrag *)((uint8_t *)(hdr) + ICMP_HDR_LEN);	\
	icmp_pack_hdr(hdr, type, code);					\
	frag_pack_p->icmp_void = 0;					\
	frag_pack_p->icmp_mtu = htons(mtu);				\
	memmove(frag_pack_p->icmp_ip, pkt, len);			\
} while (0)

#endif /* DNET_ICMP_H */
