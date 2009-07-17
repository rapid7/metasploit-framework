/*
 * ip.h
 *
 * Internet Protocol (RFC 791).
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: ip.h,v 1.25 2005/02/16 22:02:45 dugsong Exp $
 */

#ifndef DNET_IP_H
#define DNET_IP_H

#define IP_ADDR_LEN	4		/* IP address length */
#define IP_ADDR_BITS	32		/* IP address bits */

#define IP_HDR_LEN	20		/* base IP header length */
#define IP_OPT_LEN	2		/* base IP option length */
#define IP_OPT_LEN_MAX	40
#define IP_HDR_LEN_MAX	(IP_HDR_LEN + IP_OPT_LEN_MAX)

#define IP_LEN_MAX	65535
#define IP_LEN_MIN	IP_HDR_LEN

typedef uint32_t	ip_addr_t;

#ifndef __GNUC__
# define __attribute__(x)
# pragma pack(1)
#endif

/*
 * IP header, without options
 */
struct ip_hdr {
#if DNET_BYTESEX == DNET_BIG_ENDIAN
	uint8_t		ip_v:4,		/* version */
			ip_hl:4;	/* header length (incl any options) */
#elif DNET_BYTESEX == DNET_LIL_ENDIAN
	uint8_t		ip_hl:4,
			ip_v:4;
#else
# error "need to include <dnet.h>"	
#endif
	uint8_t		ip_tos;		/* type of service */
	uint16_t	ip_len;		/* total length (incl header) */
	uint16_t	ip_id;		/* identification */
	uint16_t	ip_off;		/* fragment offset and flags */
	uint8_t		ip_ttl;		/* time to live */
	uint8_t		ip_p;		/* protocol */
	uint16_t	ip_sum;		/* checksum */
	ip_addr_t	ip_src;		/* source address */
	ip_addr_t	ip_dst;		/* destination address */
};

/*
 * Type of service (ip_tos), RFC 1349 ("obsoleted by RFC 2474")
 */
#define IP_TOS_DEFAULT		0x00	/* default */
#define IP_TOS_LOWDELAY		0x10	/* low delay */
#define IP_TOS_THROUGHPUT	0x08	/* high throughput */
#define IP_TOS_RELIABILITY	0x04	/* high reliability */
#define IP_TOS_LOWCOST		0x02	/* low monetary cost - XXX */
#define IP_TOS_ECT		0x02	/* ECN-capable transport */
#define IP_TOS_CE		0x01	/* congestion experienced */

/*
 * IP precedence (high 3 bits of ip_tos), hopefully unused
 */
#define IP_TOS_PREC_ROUTINE		0x00
#define IP_TOS_PREC_PRIORITY		0x20
#define IP_TOS_PREC_IMMEDIATE		0x40
#define IP_TOS_PREC_FLASH		0x60
#define IP_TOS_PREC_FLASHOVERRIDE	0x80
#define IP_TOS_PREC_CRITIC_ECP		0xa0
#define IP_TOS_PREC_INTERNETCONTROL	0xc0
#define IP_TOS_PREC_NETCONTROL		0xe0

/*
 * Fragmentation flags (ip_off)
 */
#define IP_RF		0x8000		/* reserved */
#define IP_DF		0x4000		/* don't fragment */
#define IP_MF		0x2000		/* more fragments (not last frag) */
#define IP_OFFMASK	0x1fff		/* mask for fragment offset */

/*
 * Time-to-live (ip_ttl), seconds
 */
#define IP_TTL_DEFAULT	64		/* default ttl, RFC 1122, RFC 1340 */
#define IP_TTL_MAX	255		/* maximum ttl */

/*
 * Protocol (ip_p) - http://www.iana.org/assignments/protocol-numbers
 */
#define	IP_PROTO_IP		0		/* dummy for IP */
#define IP_PROTO_HOPOPTS	IP_PROTO_IP	/* IPv6 hop-by-hop options */
#define	IP_PROTO_ICMP		1		/* ICMP */
#define	IP_PROTO_IGMP		2		/* IGMP */
#define IP_PROTO_GGP		3		/* gateway-gateway protocol */
#define	IP_PROTO_IPIP		4		/* IP in IP */
#define IP_PROTO_ST		5		/* ST datagram mode */
#define	IP_PROTO_TCP		6		/* TCP */
#define IP_PROTO_CBT		7		/* CBT */
#define	IP_PROTO_EGP		8		/* exterior gateway protocol */
#define IP_PROTO_IGP		9		/* interior gateway protocol */
#define IP_PROTO_BBNRCC		10		/* BBN RCC monitoring */
#define IP_PROTO_NVP		11		/* Network Voice Protocol */
#define	IP_PROTO_PUP		12		/* PARC universal packet */
#define IP_PROTO_ARGUS		13		/* ARGUS */
#define IP_PROTO_EMCON		14		/* EMCON */
#define IP_PROTO_XNET		15		/* Cross Net Debugger */
#define IP_PROTO_CHAOS		16		/* Chaos */
#define	IP_PROTO_UDP		17		/* UDP */
#define IP_PROTO_MUX		18		/* multiplexing */
#define IP_PROTO_DCNMEAS	19		/* DCN measurement */
#define IP_PROTO_HMP		20		/* Host Monitoring Protocol */
#define IP_PROTO_PRM		21		/* Packet Radio Measurement */
#define	IP_PROTO_IDP		22		/* Xerox NS IDP */
#define IP_PROTO_TRUNK1		23		/* Trunk-1 */
#define IP_PROTO_TRUNK2		24		/* Trunk-2 */
#define IP_PROTO_LEAF1		25		/* Leaf-1 */
#define IP_PROTO_LEAF2		26		/* Leaf-2 */
#define IP_PROTO_RDP		27		/* "Reliable Datagram" proto */
#define IP_PROTO_IRTP		28		/* Inet Reliable Transaction */
#define	IP_PROTO_TP		29 		/* ISO TP class 4 */
#define IP_PROTO_NETBLT		30		/* Bulk Data Transfer */
#define IP_PROTO_MFPNSP		31		/* MFE Network Services */
#define IP_PROTO_MERITINP	32		/* Merit Internodal Protocol */
#define IP_PROTO_SEP		33		/* Sequential Exchange proto */
#define IP_PROTO_3PC		34		/* Third Party Connect proto */
#define IP_PROTO_IDPR		35		/* Interdomain Policy Route */
#define IP_PROTO_XTP		36		/* Xpress Transfer Protocol */
#define IP_PROTO_DDP		37		/* Datagram Delivery Proto */
#define IP_PROTO_CMTP		38		/* IDPR Ctrl Message Trans */
#define IP_PROTO_TPPP		39		/* TP++ Transport Protocol */
#define IP_PROTO_IL		40		/* IL Transport Protocol */
#define IP_PROTO_IPV6		41		/* IPv6 */
#define IP_PROTO_SDRP		42		/* Source Demand Routing */
#define IP_PROTO_ROUTING	43		/* IPv6 routing header */
#define IP_PROTO_FRAGMENT	44		/* IPv6 fragmentation header */
#define IP_PROTO_RSVP		46		/* Reservation protocol */
#define	IP_PROTO_GRE		47		/* General Routing Encap */
#define IP_PROTO_MHRP		48		/* Mobile Host Routing */
#define IP_PROTO_ENA		49		/* ENA */
#define	IP_PROTO_ESP		50		/* Encap Security Payload */
#define	IP_PROTO_AH		51		/* Authentication Header */
#define IP_PROTO_INLSP		52		/* Integated Net Layer Sec */
#define IP_PROTO_SWIPE		53		/* SWIPE */
#define IP_PROTO_NARP		54		/* NBMA Address Resolution */
#define	IP_PROTO_MOBILE		55		/* Mobile IP, RFC 2004 */
#define IP_PROTO_TLSP		56		/* Transport Layer Security */
#define IP_PROTO_SKIP		57		/* SKIP */
#define IP_PROTO_ICMPV6		58		/* ICMP for IPv6 */
#define IP_PROTO_NONE		59		/* IPv6 no next header */
#define IP_PROTO_DSTOPTS	60		/* IPv6 destination options */
#define IP_PROTO_ANYHOST	61		/* any host internal proto */
#define IP_PROTO_CFTP		62		/* CFTP */
#define IP_PROTO_ANYNET		63		/* any local network */
#define IP_PROTO_EXPAK		64		/* SATNET and Backroom EXPAK */
#define IP_PROTO_KRYPTOLAN	65		/* Kryptolan */
#define IP_PROTO_RVD		66		/* MIT Remote Virtual Disk */
#define IP_PROTO_IPPC		67		/* Inet Pluribus Packet Core */
#define IP_PROTO_DISTFS		68		/* any distributed fs */
#define IP_PROTO_SATMON		69		/* SATNET Monitoring */
#define IP_PROTO_VISA		70		/* VISA Protocol */
#define IP_PROTO_IPCV		71		/* Inet Packet Core Utility */
#define IP_PROTO_CPNX		72		/* Comp Proto Net Executive */
#define IP_PROTO_CPHB		73		/* Comp Protocol Heart Beat */
#define IP_PROTO_WSN		74		/* Wang Span Network */
#define IP_PROTO_PVP		75		/* Packet Video Protocol */
#define IP_PROTO_BRSATMON	76		/* Backroom SATNET Monitor */
#define IP_PROTO_SUNND		77		/* SUN ND Protocol */
#define IP_PROTO_WBMON		78		/* WIDEBAND Monitoring */
#define IP_PROTO_WBEXPAK	79		/* WIDEBAND EXPAK */
#define	IP_PROTO_EON		80		/* ISO CNLP */
#define IP_PROTO_VMTP		81		/* Versatile Msg Transport*/
#define IP_PROTO_SVMTP		82		/* Secure VMTP */
#define IP_PROTO_VINES		83		/* VINES */
#define IP_PROTO_TTP		84		/* TTP */
#define IP_PROTO_NSFIGP		85		/* NSFNET-IGP */
#define IP_PROTO_DGP		86		/* Dissimilar Gateway Proto */
#define IP_PROTO_TCF		87		/* TCF */
#define IP_PROTO_EIGRP		88		/* EIGRP */
#define IP_PROTO_OSPF		89		/* Open Shortest Path First */
#define IP_PROTO_SPRITERPC	90		/* Sprite RPC Protocol */
#define IP_PROTO_LARP		91		/* Locus Address Resolution */
#define IP_PROTO_MTP		92		/* Multicast Transport Proto */
#define IP_PROTO_AX25		93		/* AX.25 Frames */
#define IP_PROTO_IPIPENCAP	94		/* yet-another IP encap */
#define IP_PROTO_MICP		95		/* Mobile Internet Ctrl */
#define IP_PROTO_SCCSP		96		/* Semaphore Comm Sec Proto */
#define IP_PROTO_ETHERIP	97		/* Ethernet in IPv4 */
#define	IP_PROTO_ENCAP		98		/* encapsulation header */
#define IP_PROTO_ANYENC		99		/* private encryption scheme */
#define IP_PROTO_GMTP		100		/* GMTP */
#define IP_PROTO_IFMP		101		/* Ipsilon Flow Mgmt Proto */
#define IP_PROTO_PNNI		102		/* PNNI over IP */
#define IP_PROTO_PIM		103		/* Protocol Indep Multicast */
#define IP_PROTO_ARIS		104		/* ARIS */
#define IP_PROTO_SCPS		105		/* SCPS */
#define IP_PROTO_QNX		106		/* QNX */
#define IP_PROTO_AN		107		/* Active Networks */
#define IP_PROTO_IPCOMP		108		/* IP Payload Compression */
#define IP_PROTO_SNP		109		/* Sitara Networks Protocol */
#define IP_PROTO_COMPAQPEER	110		/* Compaq Peer Protocol */
#define IP_PROTO_IPXIP		111		/* IPX in IP */
#define IP_PROTO_VRRP		112		/* Virtual Router Redundancy */
#define IP_PROTO_PGM		113		/* PGM Reliable Transport */
#define IP_PROTO_ANY0HOP	114		/* 0-hop protocol */
#define IP_PROTO_L2TP		115		/* Layer 2 Tunneling Proto */
#define IP_PROTO_DDX		116		/* D-II Data Exchange (DDX) */
#define IP_PROTO_IATP		117		/* Interactive Agent Xfer */
#define IP_PROTO_STP		118		/* Schedule Transfer Proto */
#define IP_PROTO_SRP		119		/* SpectraLink Radio Proto */
#define IP_PROTO_UTI		120		/* UTI */
#define IP_PROTO_SMP		121		/* Simple Message Protocol */
#define IP_PROTO_SM		122		/* SM */
#define IP_PROTO_PTP		123		/* Performance Transparency */
#define IP_PROTO_ISIS		124		/* ISIS over IPv4 */
#define IP_PROTO_FIRE		125		/* FIRE */
#define IP_PROTO_CRTP		126		/* Combat Radio Transport */
#define IP_PROTO_CRUDP		127		/* Combat Radio UDP */
#define IP_PROTO_SSCOPMCE	128		/* SSCOPMCE */
#define IP_PROTO_IPLT		129		/* IPLT */
#define IP_PROTO_SPS		130		/* Secure Packet Shield */
#define IP_PROTO_PIPE		131		/* Private IP Encap in IP */
#define IP_PROTO_SCTP		132		/* Stream Ctrl Transmission */
#define IP_PROTO_FC		133		/* Fibre Channel */
#define IP_PROTO_RSVPIGN	134		/* RSVP-E2E-IGNORE */
#define	IP_PROTO_RAW		255		/* Raw IP packets */
#define IP_PROTO_RESERVED	IP_PROTO_RAW	/* Reserved */
#define	IP_PROTO_MAX		255

/*
 * Option types (opt_type) - http://www.iana.org/assignments/ip-parameters
 */
#define IP_OPT_CONTROL		0x00		/* control */
#define IP_OPT_DEBMEAS		0x40		/* debugging & measurement */
#define IP_OPT_COPY		0x80		/* copy into all fragments */
#define IP_OPT_RESERVED1	0x20
#define IP_OPT_RESERVED2	0x60

#define IP_OPT_EOL	  0			/* end of option list */
#define IP_OPT_NOP	  1			/* no operation */
#define IP_OPT_SEC	 (2|IP_OPT_COPY)	/* DoD basic security */
#define IP_OPT_LSRR	 (3|IP_OPT_COPY)	/* loose source route */
#define IP_OPT_TS	 (4|IP_OPT_DEBMEAS)	/* timestamp */
#define IP_OPT_ESEC	 (5|IP_OPT_COPY)	/* DoD extended security */
#define IP_OPT_CIPSO	 (6|IP_OPT_COPY)	/* commercial security */
#define IP_OPT_RR	  7			/* record route */
#define IP_OPT_SATID	 (8|IP_OPT_COPY)	/* stream ID (obsolete) */
#define IP_OPT_SSRR	 (9|IP_OPT_COPY)	/* strict source route */
#define IP_OPT_ZSU	 10			/* experimental measurement */
#define IP_OPT_MTUP	 11			/* MTU probe */
#define IP_OPT_MTUR	 12			/* MTU reply */
#define IP_OPT_FINN	(13|IP_OPT_COPY|IP_OPT_DEBMEAS)	/* exp flow control */
#define IP_OPT_VISA	(14|IP_OPT_COPY)	/* exp access control */
#define IP_OPT_ENCODE	 15			/* ??? */
#define IP_OPT_IMITD	(16|IP_OPT_COPY)	/* IMI traffic descriptor */
#define IP_OPT_EIP	(17|IP_OPT_COPY)	/* extended IP, RFC 1385 */
#define IP_OPT_TR	(18|IP_OPT_DEBMEAS)	/* traceroute */
#define IP_OPT_ADDEXT	(19|IP_OPT_COPY)	/* IPv7 ext addr, RFC 1475 */
#define IP_OPT_RTRALT	(20|IP_OPT_COPY)	/* router alert, RFC 2113 */
#define IP_OPT_SDB	(21|IP_OPT_COPY)	/* directed bcast, RFC 1770 */
#define IP_OPT_NSAPA	(22|IP_OPT_COPY)	/* NSAP addresses */
#define IP_OPT_DPS	(23|IP_OPT_COPY)	/* dynamic packet state */
#define IP_OPT_UMP	(24|IP_OPT_COPY)	/* upstream multicast */
#define IP_OPT_MAX	 25

#define IP_OPT_COPIED(o)	((o) & 0x80)
#define IP_OPT_CLASS(o)		((o) & 0x60)
#define IP_OPT_NUMBER(o)	((o) & 0x1f)
#define IP_OPT_TYPEONLY(o)	((o) == IP_OPT_EOL || (o) == IP_OPT_NOP)

/*
 * Security option data - RFC 791, 3.1
 */
struct ip_opt_data_sec {
	uint16_t	s;		/* security */
	uint16_t	c;		/* compartments */
	uint16_t	h;		/* handling restrictions */
	uint8_t		tcc[3];		/* transmission control code */
} __attribute__((__packed__));

#define IP_OPT_SEC_UNCLASS	0x0000	/* unclassified */
#define IP_OPT_SEC_CONFID	0xf135	/* confidential */
#define IP_OPT_SEC_EFTO		0x789a	/* EFTO */
#define IP_OPT_SEC_MMMM		0xbc4d	/* MMMM */
#define IP_OPT_SEC_PROG		0x5e26	/* PROG */
#define IP_OPT_SEC_RESTR	0xaf13	/* restricted */
#define IP_OPT_SEC_SECRET	0xd788	/* secret */
#define IP_OPT_SEC_TOPSECRET	0x6bc5	/* top secret */

/*
 * {Loose Source, Record, Strict Source} Route option data - RFC 791, 3.1
 */
struct ip_opt_data_rr {
	uint8_t		ptr;		/* from start of option, >= 4 */
	uint32_t	iplist __flexarr; /* list of IP addresses */
} __attribute__((__packed__));

/*
 * Timestamp option data - RFC 791, 3.1
 */
struct ip_opt_data_ts {
	uint8_t		ptr;		/* from start of option, >= 5 */
#if DNET_BYTESEX == DNET_BIG_ENDIAN
	uint8_t		oflw:4,		/* number of IPs skipped */
	    		flg:4;		/* address[ / timestamp] flag */
#elif DNET_BYTESEX == DNET_LIL_ENDIAN
	uint8_t		flg:4,
			oflw:4;
#endif
	uint32_t	ipts __flexarr;	/* IP address [/ timestamp] pairs */
} __attribute__((__packed__));

#define IP_OPT_TS_TSONLY	0	/* timestamps only */
#define IP_OPT_TS_TSADDR	1	/* IP address / timestamp pairs */
#define IP_OPT_TS_PRESPEC	3	/* IP address / zero timestamp pairs */

/*
 * Traceroute option data - RFC 1393, 2.2
 */
struct ip_opt_data_tr {
	uint16_t	id;		/* ID number */
	uint16_t	ohc;		/* outbound hop count */
	uint16_t	rhc;		/* return hop count */
	uint32_t	origip;		/* originator IP address */
} __attribute__((__packed__));

/*
 * IP option (following IP header)
 */
struct ip_opt {
	uint8_t		opt_type;	/* option type */
	uint8_t		opt_len;	/* option length >= IP_OPT_LEN */
	union ip_opt_data {
		struct ip_opt_data_sec	sec;	   /* IP_OPT_SEC */
		struct ip_opt_data_rr	rr;	   /* IP_OPT_{L,S}RR */
		struct ip_opt_data_ts	ts;	   /* IP_OPT_TS */
		uint16_t		satid;	   /* IP_OPT_SATID */
		uint16_t		mtu;	   /* IP_OPT_MTU{P,R} */
		struct ip_opt_data_tr	tr;	   /* IP_OPT_TR */
		uint32_t		addext[2]; /* IP_OPT_ADDEXT */
		uint16_t		rtralt;    /* IP_OPT_RTRALT */
		uint32_t		sdb[9];    /* IP_OPT_SDB */
		uint8_t			data8[IP_OPT_LEN_MAX - IP_OPT_LEN];
	} opt_data;
} __attribute__((__packed__));

#ifndef __GNUC__
# pragma pack()
#endif

/*
 * Classful addressing
 */
#define	IP_CLASSA(i)		(((uint32_t)(i) & htonl(0x80000000)) == \
				 htonl(0x00000000))
#define	IP_CLASSA_NET		(htonl(0xff000000))
#define	IP_CLASSA_NSHIFT	24
#define	IP_CLASSA_HOST		(htonl(0x00ffffff))
#define	IP_CLASSA_MAX		128

#define	IP_CLASSB(i)		(((uint32_t)(i) & htonl(0xc0000000)) == \
				 htonl(0x80000000))
#define	IP_CLASSB_NET		(htonl(0xffff0000))
#define	IP_CLASSB_NSHIFT	16
#define	IP_CLASSB_HOST		(htonl(0x0000ffff))
#define	IP_CLASSB_MAX		65536

#define	IP_CLASSC(i)		(((uint32_t)(i) & htonl(0xe0000000)) == \
				 htonl(0xc0000000))
#define	IP_CLASSC_NET		(htonl(0xffffff00))
#define	IP_CLASSC_NSHIFT	8
#define	IP_CLASSC_HOST		(htonl(0x000000ff))

#define	IP_CLASSD(i)		(((uint32_t)(i) & htonl(0xf0000000)) == \
				 htonl(0xe0000000))
/* These ones aren't really net and host fields, but routing needn't know. */
#define	IP_CLASSD_NET		(htonl(0xf0000000))
#define	IP_CLASSD_NSHIFT	28
#define	IP_CLASSD_HOST		(htonl(0x0fffffff))
#define	IP_MULTICAST(i)		IP_CLASSD(i)

#define	IP_EXPERIMENTAL(i)	(((uint32_t)(i) & htonl(0xf0000000)) == \
				 htonl(0xf0000000))
#define	IP_BADCLASS(i)		(((uint32_t)(i) & htonl(0xf0000000)) == \
				 htonl(0xf0000000))
#define	IP_LOCAL_GROUP(i)	(((uint32_t)(i) & htonl(0xffffff00)) == \
				 htonl(0xe0000000))
/*
 * Reserved addresses
 */
#define IP_ADDR_ANY		(htonl(0x00000000))	/* 0.0.0.0 */
#define IP_ADDR_BROADCAST	(htonl(0xffffffff))	/* 255.255.255.255 */
#define IP_ADDR_LOOPBACK	(htonl(0x7f000001))	/* 127.0.0.1 */
#define IP_ADDR_MCAST_ALL	(htonl(0xe0000001))	/* 224.0.0.1 */
#define IP_ADDR_MCAST_LOCAL	(htonl(0xe00000ff))	/* 224.0.0.255 */

#define ip_pack_hdr(hdr, tos, len, id, off, ttl, p, src, dst) do {	\
	struct ip_hdr *ip_pack_p = (struct ip_hdr *)(hdr);		\
	ip_pack_p->ip_v = 4; ip_pack_p->ip_hl = 5;			\
	ip_pack_p->ip_tos = tos; ip_pack_p->ip_len = htons(len);	\
 	ip_pack_p->ip_id = htons(id); ip_pack_p->ip_off = htons(off);	\
	ip_pack_p->ip_ttl = ttl; ip_pack_p->ip_p = p;			\
	ip_pack_p->ip_src = src; ip_pack_p->ip_dst = dst;		\
} while (0)

typedef struct ip_handle ip_t;

__BEGIN_DECLS
ip_t	*ip_open(void);
ssize_t	 ip_send(ip_t *i, const void *buf, size_t len);
ip_t	*ip_close(ip_t *i);

char	*ip_ntop(const ip_addr_t *ip, char *dst, size_t len);
int	 ip_pton(const char *src, ip_addr_t *dst);
char	*ip_ntoa(const ip_addr_t *ip);
#define	 ip_aton ip_pton

ssize_t	 ip_add_option(void *buf, size_t len,
	    int proto, const void *optbuf, size_t optlen);
void	 ip_checksum(void *buf, size_t len);

int	 ip_cksum_add(const void *buf, size_t len, int cksum);
#define	 ip_cksum_carry(x) \
	    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))
__END_DECLS

#endif /* DNET_IP_H */
