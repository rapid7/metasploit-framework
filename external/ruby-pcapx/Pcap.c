/*
 *  Pcap.c
 *
 *  $Id: Pcap.c,v 1.10 2000/08/13 05:56:31 fukusima Exp $
 *
 *  Copyright (C) 1998-2000  Masaki Fukushima
 */

#include "ruby_pcap.h"
#include "rubysig.h"
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define DEFAULT_DATALINK	DLT_EN10MB
#define DEFAULT_SNAPLEN	68
#define DEFAULT_PROMISC	1
#define DEFAULT_TO_MS	1000
static char pcap_errbuf[PCAP_ERRBUF_SIZE];

VALUE mPcap, rbpcap_convert = Qnil;
VALUE ePcapError;
VALUE eTruncatedPacket;
VALUE cFilter;
static VALUE cCapture;
static VALUE cPcapStat;
static VALUE cDumper;

struct filter_object {
    char *expr;
    struct bpf_program program;
    int datalink;
    int snaplen;
    VALUE param;
    VALUE optimize;
    VALUE netmask;
};

#define GetFilter(obj, filter) \
    Data_Get_Struct(obj, struct filter_object, filter)


static VALUE
pcap_s_lookupdev(self)
    VALUE self;
{
    char *dev;

    dev = pcap_lookupdev(pcap_errbuf);
    if (dev == NULL) {
	rb_raise(ePcapError, "%s", pcap_errbuf);
    }
    return rb_str_new2(dev);
}

static VALUE
pcap_s_lookupnet(self, dev)
    VALUE self;
    VALUE dev;
{
    bpf_u_int32 net, mask, m;
    struct in_addr addr;

    Check_Type(dev, T_STRING);
    if (pcap_lookupnet(STR2CSTR(dev), &net, &mask, pcap_errbuf) == -1) {
	rb_raise(ePcapError, "%s", pcap_errbuf);
    }

    addr.s_addr = net;
    m = ntohl(mask);
    return rb_ary_new3(2, new_ipaddr(&addr), UINT32_2_NUM(m));
}

static VALUE
pcap_s_convert(self)
    VALUE self;
{
    return rbpcap_convert;
}

static VALUE
pcap_s_convert_set(self, val)
    VALUE self;
{
    rbpcap_convert = val;
    return Qnil;
}

/*
 * Capture object
 */

struct capture_object {
    pcap_t	*pcap;
    bpf_u_int32	netmask;
    int		dl_type;	/* data-link type (DLT_*)		*/
};

static void
closed_capture()
{
    rb_raise(rb_eRuntimeError, "device is already closed");
}

#define GetCapture(obj, cap) {\
    Data_Get_Struct(obj, struct capture_object, cap);\
    if (cap->pcap == NULL) closed_capture();\
}

/* called from GC */
static void
free_capture(cap)
     struct capture_object *cap;
{
    DEBUG_PRINT("free_capture");
    if (cap->pcap != NULL) {
	DEBUG_PRINT("closing capture");
	rb_thread_fd_close(pcap_fileno(cap->pcap));
	pcap_close(cap->pcap);
	cap->pcap = NULL;
    }
    free(cap);
}

static VALUE
capture_open_live(argc, argv, class)
     int argc;
     VALUE *argv;
     VALUE class;
{
    VALUE v_device, v_snaplen, v_promisc, v_to_ms;
    char *device;
    int snaplen, promisc, to_ms;
    int rs;
    VALUE self;
    struct capture_object *cap;
    pcap_t *pcap;
    bpf_u_int32 net, netmask;

    DEBUG_PRINT("capture_open_live");

    /* scan arg */
    rs = rb_scan_args(argc, argv, "13", &v_device, &v_snaplen,
		      &v_promisc, &v_to_ms);

    /* device */
    Check_SafeStr(v_device);
    device = RSTRING(v_device)->ptr;
    /* snaplen */
    if (rs >= 2) {
	Check_Type(v_snaplen, T_FIXNUM);
	snaplen = FIX2INT(v_snaplen);
    } else {
	snaplen = DEFAULT_SNAPLEN;
    }
    if (snaplen <  0)
	rb_raise(rb_eArgError, "invalid snaplen");
    /* promisc */
    if (rs >= 3) {
	promisc = RTEST(v_promisc);
    } else {
	promisc = DEFAULT_PROMISC;
    }
    /* to_ms */
    if (rs >= 4) {
	Check_Type(v_to_ms, T_FIXNUM);
	to_ms = FIX2INT(v_to_ms);
    } else
	to_ms = DEFAULT_TO_MS;

    /* open */
    pcap = pcap_open_live(device, snaplen, promisc, to_ms, pcap_errbuf);
    if (pcap == NULL) {
	rb_raise(ePcapError, "%s", pcap_errbuf);
    }
    if (pcap_lookupnet(device, &net, &netmask, pcap_errbuf) == -1) {
	netmask = 0;
	rb_warning("cannot lookup net: %s\n", pcap_errbuf);
    }

    /* setup instance */
    self = Data_Make_Struct(class, struct capture_object,
			    0, free_capture, cap);
    cap->pcap = pcap;
    cap->netmask = netmask;
    cap->dl_type = pcap_datalink(pcap);

    return self;
}

static VALUE
capture_open_offline(class, fname)
     VALUE class;
     VALUE fname;
{
    VALUE self;
    struct capture_object *cap;
    pcap_t *pcap;

    DEBUG_PRINT("capture_open_offline");

    /* open offline */
    Check_SafeStr(fname);
    pcap = pcap_open_offline(RSTRING(fname)->ptr, pcap_errbuf);
    if (pcap == NULL) {
	rb_raise(ePcapError, "%s", pcap_errbuf);
    }

    /* setup instance */
    self = Data_Make_Struct(class, struct capture_object,
			    0, free_capture, cap);
    cap->pcap = pcap;
    cap->netmask = 0;
    cap->dl_type = pcap_datalink(pcap);

    return self;
}

static VALUE
capture_close(self)
     VALUE self;
{
    struct capture_object *cap;

    DEBUG_PRINT("capture_close");
    GetCapture(self, cap);

    rb_thread_fd_close(pcap_fileno(cap->pcap));
    pcap_close(cap->pcap);
    cap->pcap = NULL;
    return Qnil;
}

static void
handler(cap, pkthdr, data)
     struct capture_object *cap;
     const struct pcap_pkthdr *pkthdr;
     const u_char *data;
{
    rb_yield(new_packet(data, pkthdr, cap->dl_type));
}

static VALUE
capture_dispatch(argc, argv, self)
     int argc;
     VALUE *argv;
     VALUE self;
{
    VALUE v_cnt;
    int cnt;
    struct capture_object *cap;
    int ret;

    DEBUG_PRINT("capture_dispatch");
    GetCapture(self, cap);


    /* scan arg */
    if (rb_scan_args(argc, argv, "01", &v_cnt) >= 1) {
	FIXNUM_P(v_cnt);
	cnt = FIX2INT(v_cnt);
    } else
	cnt = -1;

    TRAP_BEG;
    ret = pcap_dispatch(cap->pcap, cnt, handler, (u_char *)cap);
    TRAP_END;
    if (ret == -1)
	rb_raise(ePcapError, "dispatch: %s", pcap_geterr(cap->pcap));

    return INT2FIX(ret);
}

int pcap_read(pcap_t *, int cnt, pcap_handler, u_char *); /* pcap-int.h */

static VALUE
capture_loop(argc, argv, self)
     int argc;
     VALUE *argv;
     VALUE self;
{
    VALUE v_cnt;
    int cnt;
    struct capture_object *cap;
    int ret;

    DEBUG_PRINT("capture_loop");
    GetCapture(self, cap);


    /* scan arg */
    if (rb_scan_args(argc, argv, "01", &v_cnt) >= 1) {
	FIXNUM_P(v_cnt);
	cnt = FIX2INT(v_cnt);
    } else
	cnt = -1;

#if 0
    TRAP_BEG;
    ret = pcap_loop(cap->pcap, cnt, handler, (u_char *)cap);
    TRAP_END;
#else
    if (pcap_file(cap->pcap) != NULL) {
	TRAP_BEG;
	ret = pcap_loop(cap->pcap, cnt, handler, (u_char *)cap);
	TRAP_END;
    } else {
	int fd = pcap_fileno(cap->pcap);
	fd_set rset;
	struct timeval tm;

	FD_ZERO(&rset);
	tm.tv_sec = 0;
	tm.tv_usec = 0;
	for (;;) {
	    do {
		FD_SET(fd, &rset);
		if (select(fd+1, &rset, NULL, NULL, &tm) == 0) {
		    rb_thread_wait_fd(fd);
		}
		TRAP_BEG;
		ret = pcap_read(cap->pcap, 1, handler, (u_char *)cap);
		TRAP_END;
	    } while (ret == 0);
	    if (ret <= 0)
		break;
	    if (cnt > 0) {
		cnt -= ret;
		if (cnt <= 0)
		    break;
	    }
	}
    }
#endif
    return INT2FIX(ret);
}

static VALUE
capture_setfilter(argc, argv, self)
     int argc;
     VALUE *argv;
     VALUE self;
{
    struct capture_object *cap;
    VALUE vfilter, optimize;
    char *filter;
    int opt;
    struct bpf_program program;

    DEBUG_PRINT("capture_setfilter");
    GetCapture(self, cap);

    /* scan arg */
    if (rb_scan_args(argc, argv, "11", &vfilter, &optimize) == 1) {
	optimize = Qtrue;
    }

    /* check arg */
    if (IsKindOf(vfilter, cFilter)) {
	struct filter_object *f;
	GetFilter(vfilter, f);
	filter = f->expr;
    } else {
	Check_Type(vfilter, T_STRING);
	filter = RSTRING(vfilter)->ptr;
    }
    opt = RTEST(optimize);

    /* operation */
    if (pcap_compile(cap->pcap, &program, filter,
		     opt, cap->netmask) < 0)
	rb_raise(ePcapError, "setfilter: %s", pcap_geterr(cap->pcap));
    if (pcap_setfilter(cap->pcap, &program) < 0)
	rb_raise(ePcapError, "setfilter: %s", pcap_geterr(cap->pcap));
    
    return Qnil;
}

static VALUE
capture_datalink(self)
     VALUE self;
{
    struct capture_object *cap;

    DEBUG_PRINT("capture_datalink");
    GetCapture(self, cap);

    return INT2NUM(pcap_datalink(cap->pcap));
}

static VALUE
capture_snapshot(self)
     VALUE self;
{
    struct capture_object *cap;

    DEBUG_PRINT("capture_snapshot");
    GetCapture(self, cap);

    return INT2NUM(pcap_snapshot(cap->pcap));
}

static VALUE
capture_stats(self)
     VALUE self;
{
    struct capture_object *cap;
    struct pcap_stat stat;
    VALUE v_stat;

    DEBUG_PRINT("capture_stats");
    GetCapture(self, cap);

    if (pcap_stats(cap->pcap, &stat) == -1)
	return Qnil;

    v_stat = rb_funcall(cPcapStat, rb_intern("new"), 3,
			UINT2NUM(stat.ps_recv),
			UINT2NUM(stat.ps_drop),
			UINT2NUM(stat.ps_ifdrop));

    return v_stat;
}

/*
 * Dumper object
 */

struct dumper_object {
    pcap_dumper_t *pcap_dumper;
    int dl_type;
    bpf_u_int32 snaplen;
};

static void
closed_dumper()
{
    rb_raise(rb_eRuntimeError, "dumper is already closed");
}

#define GetDumper(obj, dumper) {\
    Data_Get_Struct(obj, struct dumper_object, dumper);\
    if (dumper->pcap_dumper == NULL) closed_dumper();\
}

/* called from GC */
static void
free_dumper(dumper)
     struct dumper_object *dumper;
{
    DEBUG_PRINT("free_dumper");
    if (dumper->pcap_dumper != NULL) {
	DEBUG_PRINT("closing dumper");
	pcap_dump_close(dumper->pcap_dumper);
	dumper->pcap_dumper = NULL;
    }
    free(dumper);
}

static VALUE
dumper_open(class, v_cap, v_fname)
     VALUE class;
     VALUE v_cap;
     VALUE v_fname;
{
    struct dumper_object *dumper;
    struct capture_object *cap;
    pcap_dumper_t *pcap_dumper;
    VALUE self;

    DEBUG_PRINT("dumper_open");

    CheckClass(v_cap, cCapture);
    GetCapture(v_cap, cap);
    Check_SafeStr(v_fname);

    pcap_dumper = pcap_dump_open(cap->pcap, RSTRING(v_fname)->ptr);
    if (pcap_dumper == NULL) {
	rb_raise(ePcapError, "dumper_open: %s", pcap_geterr(cap->pcap));
    }

    self = Data_Make_Struct(class, struct dumper_object, 0,
			    free_dumper, dumper);
    dumper->pcap_dumper = pcap_dumper;
    dumper->dl_type = cap->dl_type;
    dumper->snaplen = pcap_snapshot(cap->pcap);

    return self;
}

static VALUE
dumper_close(self)
     VALUE self;
{
    struct dumper_object *dumper;

    DEBUG_PRINT("dumper_close");
    GetDumper(self, dumper);

    pcap_dump_close(dumper->pcap_dumper);
    dumper->pcap_dumper = NULL;
    return Qnil;
}

static VALUE
dumper_dump(self, v_pkt)
     VALUE self;
     VALUE v_pkt;
{
    struct dumper_object *dumper;
    struct packet_object *pkt;

    DEBUG_PRINT("dumper_dump");
    GetDumper(self, dumper);

    CheckClass(v_pkt, cPacket);
    GetPacket(v_pkt, pkt);
    if (pkt->hdr.dl_type != dumper->dl_type)
	rb_raise(rb_eArgError, "Cannot dump this packet: data-link type mismatch");
    if (pkt->hdr.pkthdr.caplen > dumper->snaplen)
	rb_raise(rb_eArgError, "Cannot dump this packet: too large caplen");

    pcap_dump((u_char *)dumper->pcap_dumper, &pkt->hdr.pkthdr, pkt->data);
    return Qnil;
}

/*
 * Filter object
 */

/* called from GC */
static void
mark_filter(filter)
     struct filter_object *filter;
{
    rb_gc_mark(filter->param);
    rb_gc_mark(filter->optimize);
    rb_gc_mark(filter->netmask);
}

static void
free_filter(filter)
     struct filter_object *filter;
{
    free(filter->expr);
    free(filter);
    /*
     * This cause memory leak because filter->program hold some memory.
     * We overlook it because libpcap does not implement pcap_freecode().
     */
}

static VALUE
filter_new(argc, argv, class)
     int argc;
     VALUE *argv;
     VALUE class;
{
    VALUE self, v_expr, v_optimize, v_capture, v_netmask;
    struct filter_object *filter;
    struct capture_object *capture;
    pcap_t *pcap;
    char *expr;
    int n, optimize, snaplen, linktype;
    bpf_u_int32 netmask;

    n = rb_scan_args(argc, argv, "13", &v_expr, &v_capture,
		     &v_optimize, &v_netmask);
    /* filter expression */
    Check_Type(v_expr, T_STRING);
    expr = STR2CSTR(v_expr);
    /* capture object */
    if (IsKindOf(v_capture, cCapture)) {
	CheckClass(v_capture, cCapture);
	GetCapture(v_capture, capture);
	pcap = capture->pcap;
    } else if (NIL_P(v_capture)) {
	/* assume most common case */
	snaplen  = DEFAULT_SNAPLEN;
	linktype = DEFAULT_DATALINK;
	pcap = 0;
    } else {
	snaplen  = NUM2INT(rb_funcall(v_capture, rb_intern("[]"), 1, INT2FIX(0)));
	linktype = NUM2INT(rb_funcall(v_capture, rb_intern("[]"), 1, INT2FIX(1)));
	pcap = 0;
    }
    /* optimize flag */
    optimize = 1;
    if (n >= 3) {
	optimize = RTEST(v_optimize);
    }
    /* netmask */
    netmask = 0;
    if (n >= 4) {
	bpf_u_int32 mask = NUM2UINT(v_netmask);
	netmask = htonl(mask);
    }

    filter = (struct filter_object *)xmalloc(sizeof(struct filter_object));
    if (pcap) {
	if (pcap_compile(pcap, &filter->program, expr, optimize, netmask) < 0)
	    rb_raise(ePcapError, "%s", pcap_geterr(pcap));
	filter->datalink = pcap_datalink(pcap);
	filter->snaplen  = pcap_snapshot(pcap);
    } else {
#ifdef HAVE_PCAP_COMPILE_NOPCAP
	if (pcap_compile_nopcap(snaplen, linktype, &filter->program, expr, optimize, netmask) < 0)
	    /* libpcap-0.5 provides no error report for pcap_compile_nopcap */
	    rb_raise(ePcapError, "pcap_compile_nopcap error");
	filter->datalink = linktype;
	filter->snaplen  = snaplen;
#else
	rb_raise(rb_eArgError, "pcap_compile_nopcap needs libpcap-0.5 or later");
#endif
    }
    self = Data_Wrap_Struct(class, mark_filter, free_filter, filter);
    filter->expr	= strdup(expr);
    filter->param	= v_capture;
    filter->optimize	= optimize ? Qtrue : Qfalse;
    filter->netmask	= INT2NUM(ntohl(netmask));

    return self;
}

VALUE
filter_match(self, v_pkt)
    VALUE self, v_pkt;
{
    struct filter_object *filter;
    struct packet_object *pkt;
    struct pcap_pkthdr *h;

    GetFilter(self, filter);
    CheckClass(v_pkt, cPacket);
    GetPacket(v_pkt, pkt);
    h = &pkt->hdr.pkthdr;

    if (filter->datalink != pkt->hdr.dl_type)
	rb_raise(rb_eRuntimeError, "Incompatible datalink type");
    if (filter->snaplen < h->caplen)
	rb_raise(rb_eRuntimeError, "Incompatible snaplen");

    if (bpf_filter(filter->program.bf_insns, pkt->data, h->len, h->caplen))
	return Qtrue;
    else
	return Qfalse;
}

static VALUE
filter_source(self)
    VALUE self;
{
    struct filter_object *filter;

    GetFilter(self, filter);
    return rb_str_new2(filter->expr);
}

static VALUE
new_filter(expr, param, optimize, netmask)
    char *expr;
    VALUE param, optimize, netmask;
{
    return rb_funcall(cFilter,
		      rb_intern("new"), 4,
		      rb_str_new2(expr), param, optimize, netmask);
}

static VALUE
filter_or(self, other)
    VALUE self, other;
{
    struct filter_object *filter, *filter2;
    char *expr;

    CheckClass(other, cFilter);
    GetFilter(self, filter);
    GetFilter(other, filter2);

    expr = ALLOCA_N(char, strlen(filter->expr) + strlen(filter2->expr) + 16); 
    sprintf(expr, "( %s ) or ( %s )", filter->expr, filter2->expr);
    return new_filter(expr, filter->param, filter->optimize, filter->netmask);
}

static VALUE
filter_and(self, other)
    VALUE self, other;
{
    struct filter_object *filter, *filter2;
    char *expr;

    CheckClass(other, cFilter);
    GetFilter(self, filter);
    GetFilter(other, filter2);

    expr = ALLOCA_N(char, strlen(filter->expr) + strlen(filter2->expr) + 16); 
    sprintf(expr, "( %s ) and ( %s )", filter->expr, filter2->expr);
    return new_filter(expr, filter->param, filter->optimize, filter->netmask);
}

static VALUE
filter_not(self)
    VALUE self;
{
    struct filter_object *filter;
    char *expr;

    GetFilter(self, filter);
    expr = ALLOCA_N(char, strlen(filter->expr) + 16); 
    sprintf(expr, "not ( %s )", filter->expr);
    return new_filter(expr, filter->param, filter->optimize, filter->netmask);
}

/*
 * Class definition
 */

void
Init_PcapX(void)
{
    DEBUG_PRINT("Init_PcapX");

    /* define module Pcap */
    mPcap = rb_define_module("PcapX");
    rb_define_module_function(mPcap, "lookupdev", pcap_s_lookupdev, 0);
    rb_define_module_function(mPcap, "lookupnet", pcap_s_lookupnet, 1);
    rb_global_variable(&rbpcap_convert);
    rb_define_singleton_method(mPcap, "convert?", pcap_s_convert, 0);
    rb_define_singleton_method(mPcap, "convert=", pcap_s_convert_set, 1);
	
    rb_define_const(mPcap, "DLT_NULL",   INT2NUM(DLT_NULL));
    rb_define_const(mPcap, "DLT_EN10MB", INT2NUM(DLT_EN10MB));
    rb_define_const(mPcap, "DLT_EN3MB", INT2NUM(DLT_EN3MB));
    rb_define_const(mPcap, "DLT_AX25", INT2NUM(DLT_AX25));
    rb_define_const(mPcap, "DLT_PRONET", INT2NUM(DLT_PRONET));
    rb_define_const(mPcap, "DLT_CHAOS", INT2NUM(DLT_CHAOS));
    rb_define_const(mPcap, "DLT_IEEE802", INT2NUM(DLT_IEEE802));
    rb_define_const(mPcap, "DLT_ARCNET", INT2NUM(DLT_ARCNET));
    rb_define_const(mPcap, "DLT_SLIP", INT2NUM(DLT_SLIP));
    rb_define_const(mPcap, "DLT_PPP", INT2NUM(DLT_PPP));
    rb_define_const(mPcap, "DLT_FDDI", INT2NUM(DLT_FDDI));
    rb_define_const(mPcap, "DLT_ATM_RFC1483", INT2NUM(DLT_ATM_RFC1483));
#ifdef DLT_RAW
    rb_define_const(mPcap, "DLT_RAW", INT2NUM(DLT_RAW));
    rb_define_const(mPcap, "DLT_SLIP_BSDOS", INT2NUM(DLT_SLIP_BSDOS));
    rb_define_const(mPcap, "DLT_PPP_BSDOS", INT2NUM(DLT_PPP_BSDOS));
#endif
	rb_define_const(mPcap, "DLT_IEEE802_11", INT2NUM(DLT_IEEE802_11));
	rb_define_const(mPcap, "DLT_IEEE802_11_RADIO", INT2NUM(DLT_IEEE802_11_RADIO));
	rb_define_const(mPcap, "DLT_IEEE802_11_RADIO_AVS", INT2NUM(DLT_IEEE802_11_RADIO_AVS));
	rb_define_const(mPcap, "DLT_LINUX_SLL", INT2NUM(DLT_LINUX_SLL));
	rb_define_const(mPcap, "DLT_PRISM_HEADER", INT2NUM(DLT_PRISM_HEADER));
	rb_define_const(mPcap, "DLT_AIRONET_HEADER", INT2NUM(DLT_AIRONET_HEADER));
	
    /* define class Capture */
    cCapture = rb_define_class_under(mPcap, "Capture", rb_cObject);
    rb_include_module(cCapture, rb_mEnumerable);
    rb_define_singleton_method(cCapture, "open_live", capture_open_live, -1);
    rb_define_singleton_method(cCapture, "open_offline", capture_open_offline, 1);
    rb_define_method(cCapture, "close", capture_close, 0);
    rb_define_method(cCapture, "dispatch", capture_dispatch, -1);
    rb_define_method(cCapture, "loop", capture_loop, -1);
    rb_define_method(cCapture, "each_packet", capture_loop, -1);
    rb_define_method(cCapture, "each", capture_loop, -1);
    rb_define_method(cCapture, "setfilter", capture_setfilter, -1);
    rb_define_method(cCapture, "datalink", capture_datalink, 0);
    rb_define_method(cCapture, "snapshot", capture_snapshot, 0);
    rb_define_method(cCapture, "snaplen", capture_snapshot, 0);
    rb_define_method(cCapture, "stats", capture_stats, 0);

    /* define class Dumper */
    cDumper = rb_define_class_under(mPcap, "Dumper", rb_cObject);
    rb_define_singleton_method(cDumper, "open", dumper_open, 2);
    rb_define_method(cDumper, "close", dumper_close, 0);
    rb_define_method(cDumper, "dump", dumper_dump, 1);

    /* define class Filter */
    cFilter = rb_define_class_under(mPcap, "Filter", rb_cObject);
    rb_define_singleton_method(cFilter, "new", filter_new, -1);
    rb_define_singleton_method(cFilter, "compile", filter_new, -1);
    rb_define_method(cFilter, "=~", filter_match, 1);
    rb_define_method(cFilter, "===", filter_match, 1);
    rb_define_method(cFilter, "source", filter_source, 0);
    rb_define_method(cFilter, "|", filter_or, 1);
    rb_define_method(cFilter, "&", filter_and, 1);
    rb_define_method(cFilter, "~@", filter_not, 0);
    /*rb_define_method(cFilter, "&", filter_and, 1);*/

    /* define class PcapStat */
    cPcapStat = rb_funcall(rb_cStruct, rb_intern("new"), 4,
			   Qnil,
			   ID2SYM(rb_intern("recv")),
			   ID2SYM(rb_intern("drop")),
			   ID2SYM(rb_intern("ifdrop")));
    rb_define_const(mPcap, "Stat", cPcapStat);

    /* define exception classes */
    ePcapError       = rb_define_class_under(mPcap, "PcapError", rb_eStandardError);
    eTruncatedPacket = rb_define_class_under(mPcap, "TruncatedPacket", ePcapError);

    Init_packet();
    rb_f_require(Qnil, rb_str_new2("pcapx_misc"));
}
