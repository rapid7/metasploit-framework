/*
 *  icmp_packet.c
 *
 *  $Id: icmp_packet.c,v 1.1.1.1 1999/10/27 09:54:38 fukusima Exp $
 *
 *  Copyright (C) 1999  Masaki Fukushima
 */

#include "ruby_pcap.h"

/* rfc1256 */
#ifndef ICMP_ROUTERADVERT
#define ICMP_ROUTERADVERT  9
#endif
#ifndef ICMP_ROUTERSOLICIT
#define ICMP_ROUTERSOLICIT 10
#endif

/* rfc1393 */
#ifndef ICMP_TROUTE
#define ICMP_TROUTE        30
#endif

/* rfc1788 */
#ifndef ICMP_DOMAIN
#define ICMP_DOMAIN        37
#endif
#ifndef ICMP_DOMAINREPLY
#define ICMP_DOMAINREPLY   38
#endif

/* rfc1700 */
#ifndef ICMP_UNREACH_NET_UNKNOWN
#define ICMP_UNREACH_NET_UNKNOWN	6
#endif
#ifndef ICMP_UNREACH_HOST_UNKNOWN
#define ICMP_UNREACH_HOST_UNKNOWN	7
#endif
#ifndef ICMP_UNREACH_ISOLATED
#define ICMP_UNREACH_ISOLATED		8
#endif
#ifndef ICMP_UNREACH_NET_PROHIB
#define ICMP_UNREACH_NET_PROHIB		9
#endif
#ifndef ICMP_UNREACH_HOST_PROHIB
#define ICMP_UNREACH_HOST_PROHIB	10
#endif
#ifndef ICMP_UNREACH_TOSNET
#define ICMP_UNREACH_TOSNET		11
#endif
#ifndef ICMP_UNREACH_TOSHOST
#define ICMP_UNREACH_TOSHOST		12
#endif

/* rfc1716 */
#ifndef ICMP_UNREACH_FILTER_PROHIB
#define ICMP_UNREACH_FILTER_PROHIB	13
#endif
#ifndef ICMP_UNREACH_HOST_PRECEDENCE
#define ICMP_UNREACH_HOST_PRECEDENCE	14
#endif
#ifndef ICMP_UNREACH_PRECEDENCE_CUTOFF
#define ICMP_UNREACH_PRECEDENCE_CUTOFF	15
#endif

#ifndef ICMP_PARAMPROB_OPTABSENT
#define ICMP_PARAMPROB_OPTABSENT	1
#endif

#define ICMP_HDR(pkt)  ((struct icmp *)LAYER4_HDR(pkt))
#define ICMP_DATA(pkt) ((u_char *)LAYER5_HDR(pkt))
#define ICMP_DATALEN(pkt) \
    (ntohs(IP_HDR(pkt)->ip_len) - (IP_HDR(pkt)->ip_hl * 4 + 8))
#define ICMP_CAPLEN(pkt) (pkt->hdr.pkthdr.caplen - pkt->hdr.layer4_off)

VALUE cICMPPacket;

#define CheckTruncateICMP(pkt, need) \
    CheckTruncate(pkt, pkt->hdr.layer4_off, need, "truncated ICMP")

struct icmp_type_info {
    char *name;
    VALUE klass;
};
static struct icmp_type_info icmp_types[] = {
    {/*  0 */ "echo reply"           },
    {},{},
    {/*  3 */ "unreachable"          },
    {/*  4 */ "source quench"        },
    {/*  5 */ "redirect"             },
    {},{},
    {/*  8 */ "echo request"         },
    {/*  9 */ "router advertisement" },
    {/* 10 */ "router solicitation"  },
    {/* 11 */ "time exceeded"        },
    {/* 12 */ "parameter problem"    },
    {/* 13 */ "time stamp request"   },
    {/* 14 */ "time stamp reply"     },
    {/* 15 */ "information request"  },
    {/* 16 */ "information reply"    },
    {/* 17 */ "address mask request" },
    {/* 18 */ "address mask reply"   },
    {},{},{},{},{},{},{},{},{},{},{},
    {/* 30 */ "traceroute"           },
    {},{},{},{},{},{},
    {/* 37 */ "domain name request"  },
    {/* 38 */ "domain name reply"    }
#define ICMP_TYPE_MAX 38
};

VALUE
setup_icmp_packet(pkt, tl_len)
     struct packet_object *pkt;
     int tl_len;
{
    VALUE klass =  cICMPPacket;

    if (tl_len >= 1) {
	struct icmp *icmp = ICMP_HDR(pkt);
	if (icmp->icmp_type <= ICMP_TYPE_MAX
	    && icmp_types[icmp->icmp_type].klass) {
	    klass = icmp_types[icmp->icmp_type].klass;
	}
    }
    return klass;
}


#define ICMPP_METHOD(func, need, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct packet_object *pkt;\
    struct icmp *icmp;\
    GetPacket(self, pkt);\
    CheckTruncateICMP(pkt, (need));\
    icmp = ICMP_HDR(pkt);\
    return (val);\
}

/*
 * Common methods (icmp_type independent)
 */

ICMPP_METHOD(icmpp_type,   1, INT2FIX(icmp->icmp_type))
ICMPP_METHOD(icmpp_code,   2, INT2FIX(icmp->icmp_code))
ICMPP_METHOD(icmpp_cksum,  4, INT2FIX(ntohs(icmp->icmp_cksum)))
ICMPP_METHOD(icmpp_typestr, 1,
	     (icmp->icmp_type <= ICMP_TYPE_MAX
	      &&icmp_types[icmp->icmp_type].name)
	     ? rb_str_new2(icmp_types[icmp->icmp_type].name)
	     : rb_obj_as_string(INT2FIX(icmp->icmp_type)))

			 			 
/*
 * icmp_type specific methods
 */

ICMPP_METHOD(icmpp_pptr,   5, INT2FIX(icmp->icmp_pptr))
ICMPP_METHOD(icmpp_gwaddr, 8, new_ipaddr(&icmp->icmp_gwaddr))
ICMPP_METHOD(icmpp_id,     6, INT2FIX(ntohs(icmp->icmp_id)))
ICMPP_METHOD(icmpp_seq,    8, INT2FIX(ntohs(icmp->icmp_seq)))
#ifdef WORDS_BIGENDIAN
ICMPP_METHOD(icmpp_seqle,  8, INT2FIX(((0x00ff&icmp->icmp_seq)<<8) +
				      (icmp->icmp_seq >> 8)))
#else
ICMPP_METHOD(icmpp_seqle,  8, INT2FIX(icmp->icmp_seq))
#endif

/* rfc1191 */
struct mtu_discovery {
    u_short unused;
    u_short nextmtu;
};
#define MTUD(icmp) ((struct mtu_discovery *)&icmp->icmp_void)

static VALUE
icmpp_nextmtu(self)
     VALUE self;
{
    struct packet_object *pkt;
    struct icmp *icmp;

    GetPacket(self, pkt);
    CheckTruncateICMP(pkt, 8);
    icmp = ICMP_HDR(pkt);

    if (icmp->icmp_code != ICMP_UNREACH_NEEDFRAG)
	rb_raise(rb_eRuntimeError, "not ICMP_UNREACH_NEEDFRAG");
    return INT2FIX(ntohs(MTUD(icmp)->nextmtu));
}

/* rfc1256 */
struct ih_rdiscovery {
    u_char num_addrs;
    u_char wpa;
    u_short lifetime;
};
#define IHRD(icmp) ((struct ih_rdiscovery *)&icmp->icmp_void)

struct id_rdiscovery {
    struct in_addr ird_addr;
    long ird_pref;
};
#define IDRD(icmp) ((struct id_rdiscovery *)icmp->icmp_data)

ICMPP_METHOD(icmpp_num_addrs, 5, INT2FIX(IHRD(icmp)->num_addrs))
ICMPP_METHOD(icmpp_wpa,       6, INT2FIX(IHRD(icmp)->wpa))
ICMPP_METHOD(icmpp_lifetime,  8, INT2FIX(ntohs(IHRD(icmp)->lifetime)))

static VALUE
icmpp_radv(self, ind)
     VALUE self, ind;
{
    struct packet_object *pkt;
    struct icmp *icmp;
    int i = NUM2INT(ind);
    VALUE ary;

    GetPacket(self, pkt);
    CheckTruncateICMP(pkt, 5);
    if (i > IHRD(icmp)->num_addrs)
	rb_raise(rb_eRuntimeError, "num_addrs = %d, requested radv(%d)",
		 (int)IHRD(icmp)->num_addrs, i);

    CheckTruncateICMP(pkt, 8 + i*8);
    icmp = ICMP_HDR(pkt);

    ary = rb_ary_new();
    rb_ary_push(ary, new_ipaddr(&IDRD(icmp)->ird_addr));
    rb_ary_push(ary, INT2NUM(ntohl(IDRD(icmp)->ird_pref)));
    return ary;
}

#define time_new_msec(t) rb_time_new((t)/1000, (t)%1000 * 1000)
ICMPP_METHOD(icmpp_otime, 12, time_new_msec(ntohl(icmp->icmp_otime)))
ICMPP_METHOD(icmpp_rtime, 16, time_new_msec(ntohl(icmp->icmp_rtime)))
ICMPP_METHOD(icmpp_ttime, 20, time_new_msec(ntohl(icmp->icmp_ttime)))

static VALUE
icmpp_ip(self)
     VALUE self;
{
    struct packet_object *pkt;
    struct icmp *icmp;
    struct pcap_pkthdr pkthdr;

    GetPacket(self, pkt);
    CheckTruncateICMP(pkt, 9);
    icmp = ICMP_HDR(pkt);

    pkthdr.caplen     = ICMP_CAPLEN(pkt) - 8;
    pkthdr.len        = 0;
    pkthdr.ts.tv_sec  = 0;
    pkthdr.ts.tv_usec = 0;
    return new_packet((char *)&icmp->icmp_ip, &pkthdr, DLT_RAW);
}

ICMPP_METHOD(icmpp_mask, 12, UINT32_2_NUM(ntohl(icmp->icmp_mask)))
ICMPP_METHOD(icmpp_data,  9, rb_str_new(icmp->icmp_data, ICMP_CAPLEN(pkt)-8))

/* rfc1393 */
struct traceroute {
    u_short ohc;
    u_short rhc;
    u_long lspeed;
    u_long lmtu;
};
#define TROUTE(icmp) ((struct traceroute *)icmp->icmp_data)
ICMPP_METHOD(icmpp_ohc,    10, INT2FIX(ntohs(TROUTE(icmp)->ohc)))
ICMPP_METHOD(icmpp_rhc,    12, INT2FIX(ntohs(TROUTE(icmp)->rhc)))
ICMPP_METHOD(icmpp_lspeed, 16, UINT32_2_NUM(ntohl(TROUTE(icmp)->lspeed)))
ICMPP_METHOD(icmpp_lmtu,   20, UINT32_2_NUM(ntohl(TROUTE(icmp)->lmtu)))

/* rfc1788 */
struct domain_reply {
    u_long ttl;
    char names[1];
};
#define DOMAIN(icmp) ((struct domain_reply *)icmp->icmp_data)
ICMPP_METHOD(icmpp_ttl, 12, UINT32_2_NUM(ntohl(DOMAIN(icmp)->ttl)))

void
Init_icmp_packet(void)
{
    VALUE klass;

    rb_define_const(mPcap, "ICMP_ECHOREPLY",   INT2NUM(ICMP_ECHOREPLY));
    rb_define_const(mPcap, "ICMP_UNREACH",     INT2NUM(ICMP_UNREACH));
    rb_define_const(mPcap, "ICMP_SOURCEQUENCH",INT2NUM(ICMP_SOURCEQUENCH));
    rb_define_const(mPcap, "ICMP_REDIRECT",    INT2NUM(ICMP_REDIRECT));
    rb_define_const(mPcap, "ICMP_ECHO",        INT2NUM(ICMP_ECHO));
    rb_define_const(mPcap, "ICMP_TIMXCEED",    INT2NUM(ICMP_TIMXCEED));
    rb_define_const(mPcap, "ICMP_PARAMPROB",   INT2NUM(ICMP_PARAMPROB));
    rb_define_const(mPcap, "ICMP_TSTAMP",      INT2NUM(ICMP_TSTAMP));
    rb_define_const(mPcap, "ICMP_TSTAMPREPLY", INT2NUM(ICMP_TSTAMPREPLY));
    rb_define_const(mPcap, "ICMP_IREQ",        INT2NUM(ICMP_IREQ));
    rb_define_const(mPcap, "ICMP_IREQREPLY",   INT2NUM(ICMP_IREQREPLY));
    rb_define_const(mPcap, "ICMP_MASKREQ",     INT2NUM(ICMP_MASKREQ));
    rb_define_const(mPcap, "ICMP_MASKREPLY",   INT2NUM(ICMP_MASKREPLY));

    /* UNREACH codes */
    rb_define_const(mPcap, "ICMP_UNREACH_NET", INT2NUM(ICMP_UNREACH_NET));
    rb_define_const(mPcap, "ICMP_UNREACH_HOST", INT2NUM(ICMP_UNREACH_HOST));
    rb_define_const(mPcap, "ICMP_UNREACH_PROTOCOL", INT2NUM(ICMP_UNREACH_PROTOCOL));
    rb_define_const(mPcap, "ICMP_UNREACH_PORT", INT2NUM(ICMP_UNREACH_PORT));
    rb_define_const(mPcap, "ICMP_UNREACH_NEEDFRAG", INT2NUM(ICMP_UNREACH_NEEDFRAG));
    rb_define_const(mPcap, "ICMP_UNREACH_SRCFAIL", INT2NUM(ICMP_UNREACH_SRCFAIL));
    rb_define_const(mPcap, "ICMP_UNREACH_NET_UNKNOWN", INT2NUM(ICMP_UNREACH_NET_UNKNOWN));
    rb_define_const(mPcap, "ICMP_UNREACH_HOST_UNKNOWN", INT2NUM(ICMP_UNREACH_HOST_UNKNOWN));
    rb_define_const(mPcap, "ICMP_UNREACH_ISOLATED", INT2NUM(ICMP_UNREACH_ISOLATED));
    rb_define_const(mPcap, "ICMP_UNREACH_NET_PROHIB", INT2NUM(ICMP_UNREACH_NET_PROHIB));
    rb_define_const(mPcap, "ICMP_UNREACH_HOST_PROHIB", INT2NUM(ICMP_UNREACH_HOST_PROHIB));
    rb_define_const(mPcap, "ICMP_UNREACH_TOSNET", INT2NUM(ICMP_UNREACH_TOSNET));
    rb_define_const(mPcap, "ICMP_UNREACH_TOSHOST", INT2NUM(ICMP_UNREACH_TOSHOST));
    rb_define_const(mPcap, "ICMP_UNREACH_FILTER_PROHIB", INT2NUM(ICMP_UNREACH_FILTER_PROHIB));
    rb_define_const(mPcap, "ICMP_UNREACH_HOST_PRECEDENCE", INT2NUM(ICMP_UNREACH_HOST_PRECEDENCE));
    rb_define_const(mPcap, "ICMP_UNREACH_PRECEDENCE_CUTOFF", INT2NUM(ICMP_UNREACH_PRECEDENCE_CUTOFF));

    /* REDIRECT codes */
    rb_define_const(mPcap, "ICMP_REDIRECT_NET", INT2NUM(ICMP_REDIRECT_NET));
    rb_define_const(mPcap, "ICMP_REDIRECT_HOST", INT2NUM(ICMP_REDIRECT_HOST));
    rb_define_const(mPcap, "ICMP_REDIRECT_TOSNET", INT2NUM(ICMP_REDIRECT_TOSNET));
    rb_define_const(mPcap, "ICMP_REDIRECT_TOSHOST", INT2NUM(ICMP_REDIRECT_TOSHOST));

    /* TIMEXCEED codes */
    rb_define_const(mPcap, "ICMP_TIMXCEED_INTRANS", INT2NUM(ICMP_TIMXCEED_INTRANS));
    rb_define_const(mPcap, "ICMP_TIMXCEED_REASS", INT2NUM(ICMP_TIMXCEED_REASS));

    /* PARAMPROB code */
    rb_define_const(mPcap, "ICMP_PARAMPROB_OPTABSENT", INT2NUM(ICMP_PARAMPROB_OPTABSENT));

    cICMPPacket = rb_define_class_under(mPcap, "ICMPPacket", cIPPacket);
    rb_define_method(cICMPPacket, "icmp_type",     icmpp_type, 0);
    rb_define_method(cICMPPacket, "icmp_typestr",  icmpp_typestr, 0);
    rb_define_method(cICMPPacket, "icmp_code",     icmpp_code, 0);
    rb_define_method(cICMPPacket, "icmp_cksum",    icmpp_cksum, 0);

    klass = rb_define_class_under(mPcap, "ICMPEchoReply", cICMPPacket);
    icmp_types[ICMP_ECHOREPLY].klass = klass;
    rb_define_method(klass, "icmp_id",        icmpp_id, 0);
    rb_define_method(klass, "icmp_seq",       icmpp_seq, 0);
    rb_define_method(klass, "icmp_seqle",     icmpp_seqle, 0);
    rb_define_method(klass, "icmp_data",      icmpp_data, 0);

    klass = rb_define_class_under(mPcap, "ICMPUnreach", cICMPPacket);
    icmp_types[ICMP_UNREACH].klass = klass;
    rb_define_method(klass, "icmp_nextmtu",   icmpp_nextmtu, 0);
    rb_define_method(klass, "icmp_ip",        icmpp_ip, 0);

    klass = rb_define_class_under(mPcap, "ICMPSourceQuench", cICMPPacket);
    icmp_types[ICMP_SOURCEQUENCH].klass = klass;
    rb_define_method(klass, "icmp_ip",        icmpp_ip, 0);

    klass = rb_define_class_under(mPcap, "ICMPRedirect", cICMPPacket);
    icmp_types[ICMP_REDIRECT].klass = klass;
    rb_define_method(klass, "icmp_gwaddr",    icmpp_gwaddr, 0);
    rb_define_method(klass, "icmp_ip",        icmpp_ip, 0);

    klass = rb_define_class_under(mPcap, "ICMPEcho", cICMPPacket);
    icmp_types[ICMP_ECHO].klass = klass;
    rb_define_method(klass, "icmp_id",        icmpp_id, 0);
    rb_define_method(klass, "icmp_seq",       icmpp_seq, 0);
    rb_define_method(klass, "icmp_seqle",     icmpp_seqle, 0);
    rb_define_method(klass, "icmp_data",      icmpp_data, 0);

    klass = rb_define_class_under(mPcap, "ICMPRouterAdvert", cICMPPacket);
    icmp_types[ICMP_ROUTERADVERT].klass = klass;
    rb_define_method(klass, "icmp_num_addrs", icmpp_num_addrs, 0);
    rb_define_method(klass, "icmp_wpa",       icmpp_wpa, 0);
    rb_define_method(klass, "icmp_lifetime",  icmpp_lifetime, 0);
    rb_define_method(klass, "icmp_radv",      icmpp_radv, 1);

    klass = rb_define_class_under(mPcap, "ICMPRouterSolicit", cICMPPacket);
    icmp_types[ICMP_ROUTERSOLICIT].klass = klass;

    klass = rb_define_class_under(mPcap, "ICMPTimxceed", cICMPPacket);
    icmp_types[ICMP_TIMXCEED].klass = klass;
    rb_define_method(klass, "icmp_ip",        icmpp_ip, 0);

    klass = rb_define_class_under(mPcap, "ICMPParamProb", cICMPPacket);
    icmp_types[ICMP_PARAMPROB].klass = klass;
    rb_define_method(klass, "icmp_pptr",      icmpp_pptr, 0);
    rb_define_method(klass, "icmp_ip",        icmpp_ip, 0);

    klass = rb_define_class_under(mPcap, "ICMPTStamp", cICMPPacket);
    icmp_types[ICMP_TSTAMP].klass = klass;
    rb_define_method(klass, "icmp_id",        icmpp_id, 0);
    rb_define_method(klass, "icmp_seq",       icmpp_seq, 0);
    rb_define_method(klass, "icmp_otime",     icmpp_otime, 0);
    rb_define_method(klass, "icmp_rtime",     icmpp_rtime, 0);
    rb_define_method(klass, "icmp_ttime",     icmpp_ttime, 0);

    klass = rb_define_class_under(mPcap, "ICMPTStampReply", cICMPPacket);
    icmp_types[ICMP_TSTAMPREPLY].klass = klass;
    rb_define_method(klass, "icmp_id",        icmpp_id, 0);
    rb_define_method(klass, "icmp_seq",       icmpp_seq, 0);
    rb_define_method(klass, "icmp_otime",     icmpp_otime, 0);
    rb_define_method(klass, "icmp_rtime",     icmpp_rtime, 0);
    rb_define_method(klass, "icmp_ttime",     icmpp_ttime, 0);

    klass = rb_define_class_under(mPcap, "ICMPIReq", cICMPPacket);
    icmp_types[ICMP_IREQ].klass = klass;
    rb_define_method(klass, "icmp_id",        icmpp_id, 0);
    rb_define_method(klass, "icmp_seq",       icmpp_seq, 0);

    klass = rb_define_class_under(mPcap, "ICMPIReqReply", cICMPPacket);
    icmp_types[ICMP_IREQREPLY].klass = klass;
    rb_define_method(klass, "icmp_id",        icmpp_id, 0);
    rb_define_method(klass, "icmp_seq",       icmpp_seq, 0);

    klass = rb_define_class_under(mPcap, "ICMPMaskReq", cICMPPacket);
    icmp_types[ICMP_MASKREQ].klass = klass;
    rb_define_method(klass, "icmp_id",        icmpp_id, 0);
    rb_define_method(klass, "icmp_seq",       icmpp_seq, 0);
    /*rb_define_method(klass, "icmp_mask",      icmpp_mask, 0);*/

    klass = rb_define_class_under(mPcap, "ICMPMaskReply", cICMPPacket);
    icmp_types[ICMP_MASKREPLY].klass = klass;
    rb_define_method(klass, "icmp_id",        icmpp_id, 0);
    rb_define_method(klass, "icmp_seq",       icmpp_seq, 0);
    /*rb_define_method(klass, "icmp_mask",      icmpp_mask, 0);*/

    klass = rb_define_class_under(mPcap, "ICMPTRoute", cICMPPacket);
    icmp_types[ICMP_TROUTE].klass = klass;
    rb_define_method(klass, "icmp_id",        icmpp_id, 0);
    rb_define_method(klass, "icmp_ohc",       icmpp_ohc, 0);
    rb_define_method(klass, "icmp_rhc",       icmpp_rhc, 0);
    rb_define_method(klass, "icmp_lspeed",    icmpp_lspeed, 0);
    rb_define_method(klass, "icmp_lmtu",      icmpp_lmtu, 0);

    klass = rb_define_class_under(mPcap, "ICMPDomain", cICMPPacket);
    icmp_types[ICMP_DOMAIN].klass = klass;
    rb_define_method(klass, "icmp_id",        icmpp_id, 0);
    rb_define_method(klass, "icmp_seq",       icmpp_seq, 0);

    klass = rb_define_class_under(mPcap, "ICMPDomainReply", cICMPPacket);
    icmp_types[ICMP_DOMAINREPLY].klass = klass;
    rb_define_method(klass, "icmp_id",        icmpp_id, 0);
    rb_define_method(klass, "icmp_seq",       icmpp_seq, 0);
    rb_define_method(klass, "icmp_ttl",       icmpp_ttl, 0);
    /*rb_define_method(klass, "icmp_names",     icmpp_names, 0);*/
}
