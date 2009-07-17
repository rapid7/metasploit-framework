/*
 * tcp.h
 *
 * Transmission Control Protocol (RFC 793).
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: tcp.h,v 1.17 2004/02/23 10:02:11 dugsong Exp $
 */

#ifndef DNET_TCP_H
#define DNET_TCP_H

#define TCP_HDR_LEN	20		/* base TCP header length */
#define TCP_OPT_LEN	2		/* base TCP option length */
#define TCP_OPT_LEN_MAX	40
#define TCP_HDR_LEN_MAX	(TCP_HDR_LEN + TCP_OPT_LEN_MAX)

#ifndef __GNUC__
# define __attribute__(x)
# pragma pack(1)
#endif

/*
 * TCP header, without options
 */
struct tcp_hdr {
	uint16_t	th_sport;	/* source port */
	uint16_t	th_dport;	/* destination port */
	uint32_t	th_seq;		/* sequence number */
	uint32_t	th_ack;		/* acknowledgment number */
#if DNET_BYTESEX == DNET_BIG_ENDIAN
	uint8_t		th_off:4,	/* data offset */
			th_x2:4;	/* (unused) */
#elif DNET_BYTESEX == DNET_LIL_ENDIAN
	uint8_t		th_x2:4,
			th_off:4;
#else
# error "need to include <dnet.h>"
#endif
	uint8_t		th_flags;	/* control flags */
	uint16_t	th_win;		/* window */
	uint16_t	th_sum;		/* checksum */
	uint16_t	th_urp;		/* urgent pointer */
};

/*
 * TCP control flags (th_flags)
 */
#define TH_FIN		0x01		/* end of data */
#define TH_SYN		0x02		/* synchronize sequence numbers */
#define TH_RST		0x04		/* reset connection */
#define TH_PUSH		0x08		/* push */
#define TH_ACK		0x10		/* acknowledgment number set */
#define TH_URG		0x20		/* urgent pointer set */
#define TH_ECE		0x40		/* ECN echo, RFC 3168 */
#define TH_CWR		0x80		/* congestion window reduced */

#define TCP_PORT_MAX	65535		/* maximum port */
#define TCP_WIN_MAX	65535		/* maximum (unscaled) window */

/*
 * Sequence number comparison macros
 */
#define TCP_SEQ_LT(a,b)		((int)((a)-(b)) < 0)
#define TCP_SEQ_LEQ(a,b)	((int)((a)-(b)) <= 0)
#define TCP_SEQ_GT(a,b)		((int)((a)-(b)) > 0)
#define TCP_SEQ_GEQ(a,b)	((int)((a)-(b)) >= 0)

/*
 * TCP FSM states
 */
#define TCP_STATE_CLOSED	0	/* closed */
#define TCP_STATE_LISTEN	1	/* listening from connection */
#define TCP_STATE_SYN_SENT	2	/* active, have sent SYN */
#define TCP_STATE_SYN_RECEIVED	3	/* have sent and received SYN */

#define TCP_STATE_ESTABLISHED	4	/* established */
#define TCP_STATE_CLOSE_WAIT	5	/* rcvd FIN, waiting for close */

#define TCP_STATE_FIN_WAIT_1	6	/* have closed, sent FIN */
#define TCP_STATE_CLOSING	7	/* closed xchd FIN, await FIN-ACK */
#define TCP_STATE_LAST_ACK	8	/* had FIN and close, await FIN-ACK */

#define TCP_STATE_FIN_WAIT_2	9	/* have closed, FIN is acked */
#define TCP_STATE_TIME_WAIT	10	/* in 2*MSL quiet wait after close */
#define TCP_STATE_MAX		11

/*
 * Options (opt_type) - http://www.iana.org/assignments/tcp-parameters
 */
#define TCP_OPT_EOL		0	/* end of option list */
#define TCP_OPT_NOP		1	/* no operation */
#define TCP_OPT_MSS		2	/* maximum segment size */
#define TCP_OPT_WSCALE		3	/* window scale factor, RFC 1072 */
#define TCP_OPT_SACKOK		4	/* SACK permitted, RFC 2018 */
#define TCP_OPT_SACK		5	/* SACK, RFC 2018 */
#define TCP_OPT_ECHO		6	/* echo (obsolete), RFC 1072 */
#define TCP_OPT_ECHOREPLY	7	/* echo reply (obsolete), RFC 1072 */
#define TCP_OPT_TIMESTAMP	8	/* timestamp, RFC 1323 */
#define TCP_OPT_POCONN		9	/* partial order conn, RFC 1693 */
#define TCP_OPT_POSVC		10	/* partial order service, RFC 1693 */
#define TCP_OPT_CC		11	/* connection count, RFC 1644 */
#define TCP_OPT_CCNEW		12	/* CC.NEW, RFC 1644 */
#define TCP_OPT_CCECHO		13	/* CC.ECHO, RFC 1644 */
#define TCP_OPT_ALTSUM		14	/* alt checksum request, RFC 1146 */
#define TCP_OPT_ALTSUMDATA	15	/* alt checksum data, RFC 1146 */
#define TCP_OPT_SKEETER		16	/* Skeeter */
#define TCP_OPT_BUBBA		17	/* Bubba */
#define TCP_OPT_TRAILSUM	18	/* trailer checksum */
#define TCP_OPT_MD5		19	/* MD5 signature, RFC 2385 */
#define TCP_OPT_SCPS		20	/* SCPS capabilities */
#define TCP_OPT_SNACK		21	/* selective negative acks */
#define TCP_OPT_REC		22	/* record boundaries */
#define TCP_OPT_CORRUPT		23	/* corruption experienced */
#define TCP_OPT_SNAP		24	/* SNAP */
#define TCP_OPT_TCPCOMP		26	/* TCP compression filter */
#define TCP_OPT_MAX		27

#define TCP_OPT_TYPEONLY(type)	\
	((type) == TCP_OPT_EOL || (type) == TCP_OPT_NOP)

/*
 * TCP option (following TCP header)
 */
struct tcp_opt {
	uint8_t		opt_type;	/* option type */
	uint8_t		opt_len;	/* option length >= TCP_OPT_LEN */
	union tcp_opt_data {
		uint16_t	mss;		/* TCP_OPT_MSS */
		uint8_t		wscale;		/* TCP_OPT_WSCALE */
		uint16_t	sack[19];	/* TCP_OPT_SACK */
		uint32_t	echo;		/* TCP_OPT_ECHO{REPLY} */
		uint32_t	timestamp[2];	/* TCP_OPT_TIMESTAMP */
		uint32_t	cc;		/* TCP_OPT_CC{NEW,ECHO} */
		uint8_t		cksum;		/* TCP_OPT_ALTSUM */
		uint8_t		md5[16];	/* TCP_OPT_MD5 */
		uint8_t		data8[TCP_OPT_LEN_MAX - TCP_OPT_LEN];
	} opt_data;
} __attribute__((__packed__));

#ifndef __GNUC__
# pragma pack()
#endif

#define tcp_pack_hdr(hdr, sport, dport, seq, ack, flags, win, urp) do {	\
	struct tcp_hdr *tcp_pack_p = (struct tcp_hdr *)(hdr);		\
	tcp_pack_p->th_sport = htons(sport);				\
	tcp_pack_p->th_dport = htons(dport);				\
	tcp_pack_p->th_seq = htonl(seq);				\
	tcp_pack_p->th_ack = htonl(ack);				\
	tcp_pack_p->th_x2 = 0; tcp_pack_p->th_off = 5;			\
	tcp_pack_p->th_flags = flags;					\
	tcp_pack_p->th_win = htons(win);				\
	tcp_pack_p->th_urp = htons(urp);				\
} while (0)

#endif /* DNET_TCP_H */
