/*
 *  ip_packet.c
 *
 *  $Id: ip_packet.c,v 1.1.1.1 1999/10/27 09:54:38 fukusima Exp $
 *
 *  Copyright (C) 1998, 1999  Masaki Fukushima
 */

#include "ruby_pcap.h"
#include <netdb.h>

VALUE cIPPacket;
static VALUE cIPAddress;

#define CheckTruncateIp(pkt, need) \
    CheckTruncate(pkt, pkt->hdr.layer3_off, need, "truncated IP")

VALUE
setup_ip_packet(pkt, nl_len)
     struct packet_object *pkt;
     int nl_len;
{
    VALUE class;

    DEBUG_PRINT("setup_ip_packet");

    if (nl_len > 0 && IP_HDR(pkt)->ip_v != 4) {
	return cPacket;
    }

    class = cIPPacket;
    nl_len = MIN(nl_len, ntohs(IP_HDR(pkt)->ip_len));
    if (nl_len > 20) {
	int hl = IP_HDR(pkt)->ip_hl * 4;
	int tl_len = nl_len - hl;
	if (tl_len > 0) {
	    pkt->hdr.layer4_off = pkt->hdr.layer3_off + hl;
	    /* if this is fragment zero, setup upper layer */
	    if ((ntohs(IP_HDR(pkt)->ip_off) & IP_OFFMASK) == 0) {
		switch (IP_HDR(pkt)->ip_p) {
		case IPPROTO_TCP:
		    class = setup_tcp_packet(pkt, tl_len);
		    break;
		case IPPROTO_UDP:
		    class = setup_udp_packet(pkt, tl_len);
		    break;
		case IPPROTO_ICMP:
		    class = setup_icmp_packet(pkt, tl_len);
		    break;
		}		
	    }
	}
    }

    return class;
}

#define IPP_METHOD(func, need, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct packet_object *pkt;\
    struct ip *ip;\
\
    DEBUG_PRINT(#func);\
    GetPacket(self, pkt);\
    CheckTruncateIp(pkt, (need));\
    ip = IP_HDR(pkt);\
    return (val);\
}

IPP_METHOD(ipp_ver,    1, INT2FIX(ip->ip_v))
IPP_METHOD(ipp_hlen,   1, INT2FIX(ip->ip_hl))
IPP_METHOD(ipp_tos,    2, INT2FIX(ip->ip_tos))
IPP_METHOD(ipp_len,    4, INT2FIX(ntohs(ip->ip_len)))
IPP_METHOD(ipp_id,     6, INT2FIX(ntohs(ip->ip_id)))
IPP_METHOD(ipp_flags,  8, INT2FIX((ntohs(ip->ip_off) & ~IP_OFFMASK) >> 13))
IPP_METHOD(ipp_df,     8, ntohs(ip->ip_off) & IP_DF ? Qtrue : Qfalse)
IPP_METHOD(ipp_mf,     8, ntohs(ip->ip_off) & IP_MF ? Qtrue : Qfalse)
IPP_METHOD(ipp_off,    8, INT2FIX(ntohs(ip->ip_off) & IP_OFFMASK))
IPP_METHOD(ipp_ttl,    9, INT2FIX(ip->ip_ttl))
IPP_METHOD(ipp_proto, 10, INT2FIX(ip->ip_p))
IPP_METHOD(ipp_sum,   12, INT2FIX(ntohs(ip->ip_sum)))
IPP_METHOD(ipp_src,   16, new_ipaddr(&ip->ip_src))
IPP_METHOD(ipp_dst,   20, new_ipaddr(&ip->ip_dst))

static VALUE
ipp_sumok(self)
     VALUE self;
{
    struct packet_object *pkt;
    struct ip *ip;
    int hlen, i, sum;
    unsigned short *ipus;

    GetPacket(self, pkt);
    CheckTruncateIp(pkt, 20);
    ip = IP_HDR(pkt);

    hlen = ip->ip_hl * 4;
    CheckTruncateIp(pkt, hlen);

    ipus = (unsigned short *)ip;
    sum = 0;
    hlen /= 2; /* 16-bit word */
    for (i = 0; i < hlen; i++) {
	sum += ntohs(ipus[i]);
	sum = (sum & 0xffff) + (sum >> 16);
    }
    if (sum == 0xffff)
	return Qtrue;
    return Qfalse;
}

static VALUE
ipp_data(self)
     VALUE self;
{
    struct packet_object *pkt;
    struct ip *ip;
    int len, hlen;

    DEBUG_PRINT("ipp_data");
    GetPacket(self, pkt);
    CheckTruncateIp(pkt, 20);
    ip = IP_HDR(pkt);

    hlen = ip->ip_hl * 4;
    len = pkt->hdr.pkthdr.caplen - pkt->hdr.layer3_off - hlen;
    return rb_str_new((u_char *)ip + hlen, len);
}

/*
 * IPAddress
 */

/* IPv4 adress (32bit) is stored by immediate value */
#if SIZEOF_VOIDP < 4
# error IPAddress assumes sizeof(void *) >= 4
#endif

#define GetIPAddress(obj, addr) {\
    Check_Type(obj, T_DATA);\
    addr = (struct in_addr *)&(DATA_PTR(obj));\
}

VALUE
new_ipaddr(addr)
    struct in_addr *addr;
{
    VALUE self;

    self = Data_Wrap_Struct(cIPAddress, 0, 0, (void *)addr->s_addr);
    return self;
}

#ifndef INADDR_NONE
# define INADDR_NONE (0xffffffff)
#endif
static VALUE
ipaddr_s_new(self, val)
    VALUE self, val;
{
    struct in_addr addr;
    struct hostent *hent;
    char *hname;

    switch(TYPE(val)) {
    case T_STRING:
	hname = RSTRING(val)->ptr;
	hent = gethostbyname(hname);
	if (hent == NULL) {
	    extern int h_errno;
	    switch (h_errno) {
	    case HOST_NOT_FOUND:
		rb_raise(ePcapError, "host not found: %s", hname);
		break;
	    default:
#ifdef HAVE_HSTRERROR
		rb_raise(ePcapError, (char *)hstrerror(h_errno));
#else
		rb_raise(ePcapError, "host not found: %s", hname);
#endif
	    }
	}
	addr = *(struct in_addr *)hent->h_addr;
	break;
    case T_FIXNUM:
    case T_BIGNUM:
	addr.s_addr = htonl(NUM2ULONG(val));
	break;
    default:
	rb_raise(rb_eTypeError, "String or Integer required");
    }
    return new_ipaddr(&addr);
}

static VALUE
ipaddr_to_i(self)
    VALUE self;
{
    struct in_addr *addr;

    GetIPAddress(self, addr);
    return UINT32_2_NUM(ntohl(addr->s_addr));
}

static VALUE
ipaddr_num_s(self)
    VALUE self;
{
    struct in_addr *addr;

    GetIPAddress(self, addr);
    return rb_str_new2(inet_ntoa(*addr));
}

static VALUE
ipaddr_hostname(self)
    VALUE self;
{
    struct in_addr *addr;
    struct hostent *host;

    GetIPAddress(self, addr);
    host = gethostbyaddr((char *)&addr->s_addr, sizeof addr->s_addr, AF_INET);
    if (host == NULL)
	return ipaddr_num_s(self);
    return rb_str_new2(host->h_name);
}

static VALUE
ipaddr_to_s(self)
    VALUE self;
{
    if (RTEST(rbpcap_convert))
	return ipaddr_hostname(self);
    else
	return ipaddr_num_s(self);
}

static VALUE
ipaddr_equal(self, other)
    VALUE self, other;
{
    struct in_addr *addr1;
    struct in_addr *addr2;

    GetIPAddress(self, addr1);
    if (rb_class_of(other) == cIPAddress) {
	GetIPAddress(other, addr2);
	if (addr1->s_addr == addr2->s_addr)
	    return Qtrue;
    }
    return Qfalse;
}

static VALUE
ipaddr_hash(self)
    VALUE self;
{
    struct in_addr *addr;

    GetIPAddress(self, addr);
    return INT2FIX(ntohl(addr->s_addr));
}

static VALUE
ipaddr_dump(self, limit)
     VALUE self;
     VALUE limit;
{
    struct in_addr *addr;

    GetIPAddress(self, addr);
    return rb_str_new((char *)addr, sizeof addr);
}

static VALUE
ipaddr_s_load(klass, str)
     VALUE klass;
     VALUE str;
{
    struct in_addr addr;
    int i;

    if (RSTRING(str)->len != sizeof addr) {
	rb_raise(rb_eArgError, "dump format error (IPAddress)");
    }
    for (i = 0; i < sizeof addr; i++) {
	((char *)&addr)[i] = RSTRING(str)->ptr[i];
    }	
    return new_ipaddr(&addr);
}

void
Init_ip_packet(void)
{
    DEBUG_PRINT("Init_ip_packet");

    cIPPacket = rb_define_class_under(mPcap, "IPPacket", cPacket);

    rb_define_method(cIPPacket, "ip_ver", ipp_ver, 0);
    rb_define_method(cIPPacket, "ip_hlen", ipp_hlen, 0);
    rb_define_method(cIPPacket, "ip_tos", ipp_tos, 0);
    rb_define_method(cIPPacket, "ip_len", ipp_len, 0);
    rb_define_method(cIPPacket, "ip_id", ipp_id, 0);
    rb_define_method(cIPPacket, "ip_flags", ipp_flags, 0);
    rb_define_method(cIPPacket, "ip_df?", ipp_df, 0);
    rb_define_method(cIPPacket, "ip_mf?", ipp_mf, 0);
    rb_define_method(cIPPacket, "ip_off", ipp_off, 0);
    rb_define_method(cIPPacket, "ip_ttl", ipp_ttl, 0);
    rb_define_method(cIPPacket, "ip_proto", ipp_proto, 0);
    rb_define_method(cIPPacket, "ip_sum", ipp_sum, 0);
    rb_define_method(cIPPacket, "ip_sumok?", ipp_sumok, 0);
    rb_define_method(cIPPacket, "ip_src", ipp_src, 0);
    rb_define_method(cIPPacket, "src", ipp_src, 0);
    rb_define_method(cIPPacket, "ip_dst", ipp_dst, 0);
    rb_define_method(cIPPacket, "dst", ipp_dst, 0);
    rb_define_method(cIPPacket, "ip_data", ipp_data, 0);

    cIPAddress = rb_define_class_under(mPcap, "IPAddress", rb_cObject);
    rb_define_singleton_method(cIPAddress, "new", ipaddr_s_new, 1);
    rb_define_method(cIPAddress, "to_i", ipaddr_to_i, 0);
    rb_define_method(cIPAddress, "to_s", ipaddr_to_s, 0);
    rb_define_method(cIPAddress, "num_s", ipaddr_num_s, 0);
    rb_define_method(cIPAddress, "to_num_s", ipaddr_num_s, 0); /* BWC */
    rb_define_method(cIPAddress, "hostname", ipaddr_hostname, 0);
    rb_define_method(cIPAddress, "sym_s", ipaddr_hostname, 0);
    rb_define_method(cIPAddress, "==", ipaddr_equal, 1);
    rb_define_method(cIPAddress, "===", ipaddr_equal, 1);
    rb_define_method(cIPAddress, "eql?", ipaddr_equal, 1);
    rb_define_method(cIPAddress, "hash", ipaddr_hash, 0);

    rb_define_method(cIPAddress, "_dump", ipaddr_dump, 1);
    rb_define_singleton_method(cIPAddress, "_load", ipaddr_s_load, 1);

    Init_tcp_packet();
    Init_udp_packet();
    Init_icmp_packet();
}
