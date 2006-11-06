/*
 *  tcp_packet.c
 *
 *  $Id: tcp_packet.c,v 1.1.1.1 1999/10/27 09:54:38 fukusima Exp $
 *
 *  Copyright (C) 1998, 1999  Masaki Fukushima
 */

#include "ruby_pcap.h"
#include <limits.h>

#define TCP_HDR(pkt)	((struct tcphdr *)LAYER4_HDR(pkt))
#define TCP_DATA(pkt)	((u_char *)LAYER5_HDR(pkt))
#define TCP_DATALEN(pkt) (ntohs(IP_HDR(pkt)->ip_len) - \
    (IP_HDR(pkt)->ip_hl + TCP_HDR(pkt)->th_off) * 4)

VALUE cTCPPacket;

#define CheckTruncateTcp(pkt, need) \
    CheckTruncate(pkt, pkt->hdr.layer4_off, need, "truncated TCP")

VALUE
setup_tcp_packet(pkt, tl_len)
     struct packet_object *pkt;
     int tl_len;
{
    VALUE class;

    DEBUG_PRINT("setup_tcp_packet");

    class = cTCPPacket;
    if (tl_len > 20) {
	int hl = TCP_HDR(pkt)->th_off * 4;
	int layer5_len = tl_len - hl;
	if (layer5_len > 0) {
	    pkt->hdr.layer5_off = pkt->hdr.layer4_off + hl;
	    /* upper layer */
	}
    }
    return class;
}

#define TCPP_METHOD(func, need, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct packet_object *pkt;\
    struct tcphdr *tcp;\
    DEBUG_PRINT(#func);\
    GetPacket(self, pkt);\
    CheckTruncateTcp(pkt, (need));\
    tcp = TCP_HDR(pkt);\
    return (val);\
}

TCPP_METHOD(tcpp_sport,   2, INT2FIX(ntohs(tcp->th_sport)))
TCPP_METHOD(tcpp_dport,   4, INT2FIX(ntohs(tcp->th_dport)))
TCPP_METHOD(tcpp_seq,     8, UINT32_2_NUM(ntohl(tcp->th_seq)))
TCPP_METHOD(tcpp_acknum, 12, UINT32_2_NUM(ntohl(tcp->th_ack)))
TCPP_METHOD(tcpp_off,    13, INT2FIX(tcp->th_off))
TCPP_METHOD(tcpp_flags,  14, INT2FIX(tcp->th_flags))
TCPP_METHOD(tcpp_win,    16, INT2FIX(ntohs(tcp->th_win)))
TCPP_METHOD(tcpp_sum,    18, INT2FIX(ntohs(tcp->th_sum)))
TCPP_METHOD(tcpp_urp,    20, INT2FIX(ntohs(tcp->th_urp)))

#define TCPP_FLAG(func, flag) \
    TCPP_METHOD(func, 14, (tcp->th_flags & flag) ? Qtrue : Qfalse)
TCPP_FLAG(tcpp_fin, TH_FIN)
TCPP_FLAG(tcpp_syn, TH_SYN)
TCPP_FLAG(tcpp_rst, TH_RST)
TCPP_FLAG(tcpp_psh, TH_PUSH)
TCPP_FLAG(tcpp_ack, TH_ACK)
TCPP_FLAG(tcpp_urg, TH_URG)

static VALUE
tcpp_data(self)
     VALUE self;
{
    struct packet_object *pkt;
    VALUE v_len;
    int len;

    DEBUG_PRINT("tcpp_data");
    GetPacket(self, pkt);

    if (pkt->hdr.layer5_off == OFF_NONEXIST) return Qnil;

    len = MIN(Caplen(pkt, pkt->hdr.layer5_off), TCP_DATALEN(pkt));
    if (len < 1) return Qnil;
    return rb_str_new(TCP_DATA(pkt), len);
}

void
Init_tcp_packet(void)
{
    DEBUG_PRINT("Init_tcp_packet");

    /* define class TcpPacket */
    cTCPPacket = rb_define_class_under(mPcap, "TCPPacket", cIPPacket);

    rb_define_method(cTCPPacket, "tcp_sport", tcpp_sport, 0);
    rb_define_method(cTCPPacket, "sport", tcpp_sport, 0);
    rb_define_method(cTCPPacket, "tcp_dport", tcpp_dport, 0);
    rb_define_method(cTCPPacket, "dport", tcpp_dport, 0);
    rb_define_method(cTCPPacket, "tcp_seq", tcpp_seq, 0);
    rb_define_method(cTCPPacket, "tcp_ack", tcpp_acknum, 0);
    rb_define_method(cTCPPacket, "tcp_off", tcpp_off, 0);
    rb_define_method(cTCPPacket, "tcp_hlen", tcpp_off, 0);
    rb_define_method(cTCPPacket, "tcp_flags", tcpp_flags, 0);
    rb_define_method(cTCPPacket, "tcp_win", tcpp_win, 0);
    rb_define_method(cTCPPacket, "tcp_sum", tcpp_sum, 0);
    rb_define_method(cTCPPacket, "tcp_urp", tcpp_urp, 0);
    rb_define_method(cTCPPacket, "tcp_fin?", tcpp_fin, 0);
    rb_define_method(cTCPPacket, "tcp_syn?", tcpp_syn, 0);
    rb_define_method(cTCPPacket, "tcp_rst?", tcpp_rst, 0);
    rb_define_method(cTCPPacket, "tcp_psh?", tcpp_psh, 0);
    rb_define_method(cTCPPacket, "tcp_ack?", tcpp_ack, 0);
    rb_define_method(cTCPPacket, "tcp_urg?", tcpp_urg, 0);
    rb_define_method(cTCPPacket, "tcp_data", tcpp_data, 0);
}
