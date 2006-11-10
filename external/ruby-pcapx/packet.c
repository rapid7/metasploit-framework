/*
 *  packet.c
 *
 *  $Id: packet.c,v 1.4 2000/08/13 06:56:15 fukusima Exp $
 *
 *  Copyright (C) 1998-2000  Masaki Fukushima
 */

#include "ruby.h"
#include "ruby_pcap.h"
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#define DL_HDR(pkt)	((u_char *)LAYER2_HDR(pkt))
#define DL_DATA(pkt)	((u_char *)LAYER3_HDR(pkt))

VALUE cPacket;
static VALUE mMarshal;
int id_load;
int id_dump;

/* called from GC */
static void
free_packet(pkt)
     struct packet_object *pkt;
{
    DEBUG_PRINT("free_packet");
    free(pkt);
}

/* called from GC */
static void
mark_packet(pkt)
     struct packet_object *pkt;
{
    DEBUG_PRINT("mark_packet");
    if (pkt->udata != Qnil)
	rb_gc_mark(pkt->udata);
}

struct datalink_type {
	int type;
    int nltype_off;	/* offset of network-layer type field */
    int nl_off;		/* offset of network-layer header */
};


/* supported datalink types */
static struct datalink_type datalinks[] = {
	{ DLT_NULL, -2, 4 },
	{ DLT_EN10MB, 12, 14 },
	{ DLT_IEEE802, 20, 22 },
	{ DLT_SLIP, -2, 16 },
	{ DLT_PPP, 2, 4 },
#ifndef PCAP_FDDIPAD
    { DLT_FDDI, 19, 21 },	/* 10: DLT_FDDI */
#else
    { DLT_FDDI, 19 + PCAP_FDDIPAD, 21 + PCAP_FDDIPAD },
#endif
	{ DLT_ATM_RFC1483, 6, 8 },
	{ DLT_RAW, -2, 0 },
	{ DLT_SLIP_BSDOS, -2, 24 },
	{ DLT_PPP_BSDOS, -2, 24 },	
	{ DLT_IEEE802_11, -1, 0 },
	{ DLT_IEEE802_11_RADIO, -1, 0 }, /* radiotap is padded to 64 bytes */
	{ DLT_IEEE802_11_RADIO_AVS, -1, 0 },
	{ DLT_LINUX_SLL, -1, 0 },
	{ DLT_PRISM_HEADER, -1, 0 },
	{ DLT_AIRONET_HEADER, -1, 0 },
	{ 255, 0, 0 }
};


VALUE
new_packet(data, pkthdr, dl_type)
     const u_char *data;
     const struct pcap_pkthdr *pkthdr;
     int dl_type;
{
    VALUE class;
    struct packet_object *pkt;
    int nl_off, nl_len, nltype_off, nl_type, pad, i;
	unsigned short *f;
	int t = -1;

    DEBUG_PRINT("new_packet");

	// This is slow and needs to be rewritten
	for (i = 0; datalinks[i].type != 255; i++) {
		if (datalinks[i].type == dl_type) {
			t = i;
			break;
		}
	}
	
    /* check nework layer type and offset */
    if (t == -1)
		rb_raise(ePcapError, "Unknown data-link type (%d)", dl_type);
    
    nltype_off  = datalinks[t].nltype_off;
    nl_off      = datalinks[t].nl_off;

	/* parse the DLT header to figure it out */
    if (nltype_off == -1) {
		
		switch(dl_type) {
			case DLT_LINUX_SLL:
			default:
				if (pkthdr->caplen > 16) {
					f = (unsigned short *)(data + 4);
					i = ntohs(*f);
					if (pkthdr->caplen > i + 16 ) {
						nltype_off = i + 14;
						nl_off = i + 16;
					}
				}
				break;			
		}
	}
	
	/* assume this is raw IP */
	if (nltype_off == -2) {
		nl_type = ETHERTYPE_IP;
	/* assume Ether Type value */		
	} else if (nltype_off != -1) {
		nl_type = ntohs(*(u_short *)(data + nltype_off));
	}

	
    /* alloc memory and setup packet_object */
    pad = nl_off % 4;	/* align network layer header */
    pkt = xmalloc(sizeof(*pkt) + pad + pkthdr->caplen);
    pkt->hdr.version	= PACKET_MARSHAL_VERSION;
    pkt->hdr.flags	= 0;
    pkt->hdr.dl_type	= dl_type;
    pkt->hdr.layer3_off = OFF_NONEXIST;
    pkt->hdr.layer4_off = OFF_NONEXIST;
    pkt->hdr.layer5_off = OFF_NONEXIST;
    pkt->hdr.pkthdr	= *pkthdr;
    pkt->data = (u_char *)pkt + sizeof(*pkt) + pad;
    pkt->udata = Qnil;
	
    memcpy(pkt->data, data, pkthdr->caplen);

    nl_len = pkthdr->caplen - nl_off;
    if (nl_off >= 0 && nl_len > 0)
	pkt->hdr.layer3_off = nl_off;

    /* setup upper layer */
    class = cPacket;
    if (pkt->hdr.layer3_off != OFF_NONEXIST) {
	switch (nl_type) {
	case ETHERTYPE_IP:
	    class = setup_ip_packet(pkt, nl_len);
	    break;
	}
    }
#if DEBUG
    if (ruby_debug && TYPE(class) != T_CLASS) {
	rb_fatal("not class");
    }
#endif
    return Data_Wrap_Struct(class, mark_packet, free_packet, pkt);
}

static VALUE
packet_load(class, str)
     VALUE class;
     VALUE str;
{
    struct packet_object *pkt = NULL;
    struct packet_object_header *hdr;
    int version;
    u_char *str_ptr;

    DEBUG_PRINT("packet_load");

    str_ptr = RSTRING(str)->ptr;
    hdr = (struct packet_object_header *)str_ptr;
    version = hdr->version;
    if (version == PACKET_MARSHAL_VERSION) {
	bpf_u_int32 caplen;
	u_short layer3_off;
	int pad;

	caplen = ntohl(hdr->pkthdr.caplen);
	layer3_off = ntohs(hdr->layer3_off);
	pad = layer3_off % 4;	/* align network layer header */
	pkt = (struct packet_object *)xmalloc(sizeof(*pkt) + pad + caplen);

	pkt->hdr.version		= PACKET_MARSHAL_VERSION;
	pkt->hdr.flags			= hdr->flags;
	pkt->hdr.dl_type		= hdr->dl_type;
	pkt->hdr.layer3_off		= ntohs(hdr->layer3_off);
	pkt->hdr.layer4_off		= ntohs(hdr->layer4_off);
	pkt->hdr.layer5_off		= ntohs(hdr->layer5_off);
	pkt->hdr.pkthdr.ts.tv_sec	= ntohl(hdr->pkthdr.ts.tv_sec);
	pkt->hdr.pkthdr.ts.tv_usec	= ntohl(hdr->pkthdr.ts.tv_usec);
	pkt->hdr.pkthdr.caplen		= ntohl(hdr->pkthdr.caplen);
	pkt->hdr.pkthdr.len		= ntohl(hdr->pkthdr.len);

	pkt->data = (u_char *)pkt + sizeof(*pkt) + pad;
	memcpy(pkt->data, str_ptr + sizeof(*hdr), caplen);
	if (PKTFLAG_TEST(pkt, POH_UDATA)) {
	    int l = sizeof(*hdr) + caplen;
	    VALUE ustr = rb_str_substr(str, l, RSTRING(str)->len - l);
	    pkt->udata = rb_funcall(mMarshal, id_load, 1, ustr);
	} else {
	    pkt->udata = Qnil;
	}
	PKTFLAG_SET(pkt, POH_UDATA, (pkt->udata != Qnil));
    } else {
	rb_raise(rb_eArgError, "unknown packet marshal version(0x%x)", version);
    }

    if (pkt != NULL)
	return Data_Wrap_Struct(class, mark_packet, free_packet, pkt);
    else
	return Qnil;
}

static VALUE
packet_dump(self, limit)
     VALUE self;
     VALUE limit;
{
    struct packet_object *pkt;
    struct packet_object_header hdr;
    VALUE str;

    DEBUG_PRINT("packet_dump");
    GetPacket(self, pkt);

    hdr.version			= PACKET_MARSHAL_VERSION;
    hdr.flags			= pkt->hdr.flags;
    hdr.dl_type			= pkt->hdr.dl_type;
    hdr.layer3_off		= htons(pkt->hdr.layer3_off);
    hdr.layer4_off		= htons(pkt->hdr.layer4_off);
    hdr.layer5_off		= htons(pkt->hdr.layer5_off);
    hdr.pkthdr.ts.tv_sec	= htonl(pkt->hdr.pkthdr.ts.tv_sec);
    hdr.pkthdr.ts.tv_usec	= htonl(pkt->hdr.pkthdr.ts.tv_usec);
    hdr.pkthdr.caplen		= htonl(pkt->hdr.pkthdr.caplen);
    hdr.pkthdr.len		= htonl(pkt->hdr.pkthdr.len);

    str = rb_str_new((char *)&hdr, sizeof(hdr));
    rb_str_cat(str, pkt->data, pkt->hdr.pkthdr.caplen);
    if (pkt->udata != Qnil) {
	VALUE ustr;
	ustr = rb_funcall(mMarshal, id_dump, 1, pkt->udata);
	rb_str_concat(str, ustr);
    }
    return str;
}

static VALUE
packet_set_udata(self, val)
     VALUE self;
     VALUE val;
{
    struct packet_object *pkt;

    DEBUG_PRINT("packet_set_udata");
    GetPacket(self, pkt);

    pkt->udata = val;
    PKTFLAG_SET(pkt, POH_UDATA, (val != Qnil));
    return val;
}

static VALUE
packet_match(self, expr)
     VALUE self;
     VALUE expr;
{
    if (IsKindOf(expr, cFilter)) {
	return filter_match(expr, self);
    }
    rb_raise(rb_eArgError, "Not Filter");
}

#define PACKET_METHOD(func, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct packet_object *pkt;\
\
    DEBUG_PRINT(#func);\
    GetPacket(self, pkt);\
    return (val);\
}

PACKET_METHOD(packet_get_udata, pkt->udata);
PACKET_METHOD(packet_datalink, INT2FIX(pkt->hdr.dl_type));
PACKET_METHOD(packet_ip, rb_obj_is_kind_of(self, cIPPacket));
PACKET_METHOD(packet_tcp, rb_obj_is_kind_of(self, cTCPPacket));
PACKET_METHOD(packet_udp, rb_obj_is_kind_of(self, cUDPPacket));
PACKET_METHOD(packet_length, UINT32_2_NUM(pkt->hdr.pkthdr.len));
PACKET_METHOD(packet_caplen, UINT32_2_NUM(pkt->hdr.pkthdr.caplen));
PACKET_METHOD(packet_time, rb_time_new(pkt->hdr.pkthdr.ts.tv_sec,
				       pkt->hdr.pkthdr.ts.tv_usec));
PACKET_METHOD(packet_time_i, rb_int2inum(pkt->hdr.pkthdr.ts.tv_sec));
PACKET_METHOD(packet_raw_data, rb_str_new(pkt->data, pkt->hdr.pkthdr.caplen));

void
Init_packet(void)
{
    DEBUG_PRINT("Init_packet");

    /* define class Packet */
    cPacket = rb_define_class_under(mPcap, "Packet", rb_cObject);

    rb_define_singleton_method(cPacket, "_load", packet_load, 1);
    rb_define_method(cPacket, "_dump", packet_dump, 1);
    /* marshal backward compatibility */
    rb_define_singleton_method(cPacket, "_load_from", packet_load, 1);
    rb_define_method(cPacket, "_dump_to", packet_dump, 1);

    rb_define_method(cPacket, "udata", packet_get_udata, 0);
    rb_define_method(cPacket, "udata=", packet_set_udata, 1);
    rb_define_method(cPacket, "datalink", packet_datalink, 0);
    rb_define_method(cPacket, "ip?", packet_ip, 0);
    rb_define_method(cPacket, "tcp?", packet_tcp, 0);
    rb_define_method(cPacket, "udp?", packet_udp, 0);
    rb_define_method(cPacket, "length", packet_length, 0);
    rb_define_method(cPacket, "size", packet_length, 0);
    rb_define_method(cPacket, "caplen", packet_caplen, 0);
    rb_define_method(cPacket, "time", packet_time, 0);
    rb_define_method(cPacket, "time_i", packet_time_i, 0);
    rb_define_method(cPacket, "raw_data", packet_raw_data, 0);
    rb_define_method(cPacket, "=~", packet_match, 1);

    /* mMarshal in ruby/marshal.c is static. Why? */
    mMarshal = rb_eval_string("Marshal");
    id_load = rb_intern("load");
    id_dump = rb_intern("dump");
    Init_ip_packet();
}
