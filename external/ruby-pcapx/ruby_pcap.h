/*
 *  ruby_pcap.h
 *
 *  $Id: ruby_pcap.h,v 1.4 2000/08/13 06:56:15 fukusima Exp $
 *
 *  Copyright (C) 1998-2000  Masaki Fukushima
 */

#ifndef RUBY_PCAP_H
#define RUBY_PCAP_H

#include "ruby.h"
#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#ifndef IP_OFFMASK
# define IP_OFFMASK 0x1fff
#endif
#ifdef linux
# define __FAVOR_BSD
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef DEBUG
# define DEBUG_PRINT(x) \
    ((RTEST(ruby_debug) && RTEST(ruby_verbose))?\
    (fprintf(stderr, "%s\n", x),fflush(stderr)) : 0)
#else
# define DEBUG_PRINT(x) (0)
#endif

#define UINT32_2_NUM(i) rb_uint2inum(i)
#ifndef UINT2NUM
# define UINT2NUM(i) rb_uint2inum(i)
#endif
#define MIN(x, y)	((x)<(y) ? (x) : (y))


#define PACKET_MARSHAL_VERSION	1

/* ruby config.h defines WORDS_BIGENDIAN if big-endian */
struct packet_object_header {
#ifdef WORDS_BIGENDIAN
    u_char version:4;		/* marshal format version	*/
    u_char flags:4;		/* flags			*/
#else
    u_char flags:4;		/* flags			*/
    u_char version:4;		/* marshal format version	*/
#endif
#define POH_UDATA 0x01		/* flag: user data exists	*/
#define POH_RSVD1 0x02		/*       (reserved)		*/
#define POH_RSVD2 0x03		/*       (reserved)		*/
#define POH_RSVD3 0x04		/*       (reserved)		*/
    u_char dl_type;		/* data-link type (DLT_*)	*/
    u_short layer3_off;		/* layer 3 header offset	*/
    u_short layer4_off;		/* layer 4 header offset	*/
    u_short layer5_off;		/* layer 5 header offset	*/
#define OFF_NONEXIST 0xffff	/* offset value for non-existent layer	*/
    struct pcap_pkthdr pkthdr;	/* pcap packet header		*/
};

struct packet_object {
    struct packet_object_header hdr;	/* packet object header	*/
    u_char *data;			/* packet data		*/
    VALUE udata;			/* user data		*/
};

#define PKTFLAG_TEST(pkt, flag) ((pkt)->hdr.flags & (flag))
#define PKTFLAG_SET(pkt, flag, val) \
    ((val) ? ((pkt)->hdr.flags |= (flag)) : ((pkt)->hdr.flags &= ~(flag)))

#define LAYER2_HDR(pkt)	((pkt)->data)
#define LAYER3_HDR(pkt)	((pkt)->data + (pkt)->hdr.layer3_off)
#define LAYER4_HDR(pkt)	((pkt)->data + (pkt)->hdr.layer4_off)
#define LAYER5_HDR(pkt)	((pkt)->data + (pkt)->hdr.layer5_off)

#define GetPacket(obj, pkt) Data_Get_Struct(obj, struct packet_object, pkt)
#define Caplen(pkt, from) ((pkt)->hdr.pkthdr.caplen - (from))
#define CheckTruncate(pkt, from, need, emsg) (\
    (from) + (need) > (pkt)->hdr.pkthdr.caplen ? \
        rb_raise(eTruncatedPacket, (emsg)) : 0 \
)

#define IsKindOf(v, class) RTEST(rb_obj_is_kind_of(v, class))
#define CheckClass(v, class) ((IsKindOf(v, class)) ? 0 :\
    rb_raise(rb_eTypeError, "wrong type %s (expected %s)",\
        rb_class2name(CLASS_OF(v)), rb_class2name(class)))


/* Pcap.c */
extern VALUE mPcap, rbpcap_convert;
extern VALUE ePcapError;
extern VALUE eTruncatedPacket;
extern VALUE cFilter;
void Init_PcapX(void);
VALUE filter_match(VALUE self, VALUE v_pkt);

/* packet.c */
extern VALUE cPacket;
void Init_packet(void);
VALUE new_packet(const u_char *, const struct pcap_pkthdr *, int);

/* ip_packet.c */
#define IP_HDR(pkt)	((struct ip *)LAYER3_HDR(pkt))
#define IP_DATA(pkt)	((u_char *)LAYER4_HDR(pkt))
extern VALUE cIPPacket;
void Init_ip_packet(void);
VALUE setup_ip_packet(struct packet_object *, int);
VALUE new_ipaddr(struct in_addr *);

/* tcp_packet.c */
extern VALUE cTCPPacket;
void Init_tcp_packet(void);
VALUE setup_tcp_packet(struct packet_object *, int);

/* udp_packet.c */
extern VALUE cUDPPacket;
void Init_udp_packet(void);
VALUE setup_udp_packet(struct packet_object *, int);

/* icmp_packet.c */
extern VALUE cICMPPacket;
void Init_icmp_packet(void);
VALUE setup_icmp_packet(struct packet_object *, int);

#endif /* RUBY_PCAP_H */
