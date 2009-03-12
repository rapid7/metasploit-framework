#include "ruby.h"
#include "rubysig.h"

#include <pcap.h>

#if !defined(WIN32)
 #include <netinet/in.h>
 #include <arpa/inet.h>
#endif

#include <sys/time.h>

static VALUE rb_cPcap;

#define PCAPRUB_VERSION "0.8-dev"

#define OFFLINE 1
#define LIVE 2

typedef struct rbpcap {
    pcap_t *pd;
    pcap_dumper_t *pdt;
    char iface[256];
    char type;
} rbpcap_t;


typedef struct rbpcapjob {
	struct pcap_pkthdr hdr;
    char *pkt;
	int wtf;
} rbpcapjob_t;

static VALUE
rbpcap_s_version(VALUE class)
{
    return rb_str_new2(PCAPRUB_VERSION);	
}


static VALUE
rbpcap_s_lookupdev(VALUE self)
{
    char *dev = NULL;
    char eb[PCAP_ERRBUF_SIZE];
    VALUE ret_dev;  /* device string to return */
#if defined(WIN32)  /* pcap_lookupdev is broken on windows */    
    pcap_if_t *alldevs;
    pcap_if_t *d;

    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs(&alldevs,eb) == -1) {
        rb_raise(rb_eRuntimeError,"%s",eb);
    }

    /* Find the first interface with an address and not loopback */
    for(d = alldevs; d != NULL; d= d->next)  {
        if(d->name && d->addresses && !(d->flags & PCAP_IF_LOOPBACK)) {
            dev=d->name;
            break;
        }
    }
    
    if (dev == NULL) {
        rb_raise(rb_eRuntimeError,"%s","No valid interfaces found, Make sure WinPcap is installed.\n");
    }
    ret_dev = rb_str_new2(dev);
    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
#else
    dev = pcap_lookupdev(eb);
    if (dev == NULL) {
		rb_raise(rb_eRuntimeError, "%s", eb);
   }
    ret_dev = rb_str_new2(dev);
#endif
    return ret_dev;
}

static VALUE
rbpcap_s_lookupnet(VALUE self, VALUE dev)
{
    bpf_u_int32 net, mask, m;
    struct in_addr addr;
    char eb[PCAP_ERRBUF_SIZE];
	VALUE list;
	
    Check_Type(dev, T_STRING);
    if (pcap_lookupnet(STR2CSTR(dev), &net, &mask, eb) == -1) {
		rb_raise(rb_eRuntimeError, "%s", eb);
    }

    addr.s_addr = net;
    m = ntohl(mask);
    list = rb_ary_new();
	rb_ary_push(list, rb_str_new2((char *) inet_ntoa(addr)));
	rb_ary_push(list, UINT2NUM(m));
	return(list);
}


static int rbpcap_ready(rbpcap_t *rbp) {
	if(! rbp->pd) {
		rb_raise(rb_eArgError, "a device or pcap file must be opened first");
		return 0;
	}
	return 1;
}

static void rbpcap_close(rbpcap_t *rbp) {
	if (rbp->pd)
		pcap_close(rbp->pd);

        if (rbp->pdt)
                pcap_dump_close(rbp->pdt);

	rbp->pd = NULL;
	rbp->pdt = NULL;

	free(rbp);
}

static VALUE
rbpcap_new_s(VALUE class)
{
    VALUE self;
    rbpcap_t *rbp;

    // need to make destructor do a pcap_close later
    self = Data_Make_Struct(class, rbpcap_t, 0, rbpcap_close, rbp);
    rb_obj_call_init(self, 0, 0);

    memset(rbp, 0, sizeof(rbpcap_t));
	
    return self;
}

static VALUE
rbpcap_setfilter(VALUE self, VALUE filter)
{
    char eb[PCAP_ERRBUF_SIZE];
    rbpcap_t *rbp;
    u_int32_t mask = 0, netid = 0;
    struct bpf_program bpf;

    Data_Get_Struct(self, rbpcap_t, rbp);

    if(TYPE(filter) != T_STRING)
    	rb_raise(rb_eArgError, "filter must be a string");

	if(! rbpcap_ready(rbp)) return self; 
	
    if(rbp->type == LIVE)
    	if(pcap_lookupnet(rbp->iface, &netid, &mask, eb) < 0)
    		rb_raise(rb_eRuntimeError, "%s", eb);

    if(pcap_compile(rbp->pd, &bpf, RSTRING(filter)->ptr, 0, mask) < 0)
    	rb_raise(rb_eRuntimeError, "invalid bpf filter");

    if(pcap_setfilter(rbp->pd, &bpf) < 0)
    	rb_raise(rb_eRuntimeError, "unable to set bpf filter");

    return self;
}


static VALUE
rbpcap_open_live(VALUE self, VALUE iface,VALUE snaplen,VALUE promisc, VALUE timeout)
{
    char eb[PCAP_ERRBUF_SIZE];
    rbpcap_t *rbp;
    int promisc_value = 0;

    if(TYPE(iface) != T_STRING)
    	rb_raise(rb_eArgError, "interface must be a string");
    if(TYPE(snaplen) != T_FIXNUM)
    	rb_raise(rb_eArgError, "snaplen must be a fixnum");
    if(TYPE(timeout) != T_FIXNUM)
    	rb_raise(rb_eArgError, "timeout must be a fixnum");

    switch(promisc) {
    	case Qtrue:
    		promisc_value = 1;
    		break;
    	case Qfalse:
    		promisc_value = 0;
    		break;
    	default:
    		rb_raise(rb_eTypeError, "Argument not boolean");
    }

    Data_Get_Struct(self, rbpcap_t, rbp);

    rbp->type = LIVE;
    memset(rbp->iface, 0, sizeof(rbp->iface));
    strncpy(rbp->iface, RSTRING(iface)->ptr, sizeof(rbp->iface) - 1);

    rbp->pd = pcap_open_live(
    	RSTRING(iface)->ptr,
    	NUM2INT(snaplen),
    	promisc_value,
    	NUM2INT(timeout),
    	eb
    );

    if(!rbp->pd)
    	rb_raise(rb_eRuntimeError, "%s", eb);

    return self;
}

static VALUE
rbpcap_open_live_s(VALUE class, VALUE iface, VALUE snaplen, VALUE promisc, VALUE timeout)
{
    VALUE iPcap = rb_funcall(rb_cPcap, rb_intern("new"), 0);
    return rbpcap_open_live(iPcap, iface, snaplen, promisc, timeout);
}

static VALUE
rbpcap_open_offline(VALUE self, VALUE filename)
{
    char eb[PCAP_ERRBUF_SIZE];
    rbpcap_t *rbp;

    if(TYPE(filename) != T_STRING)
    	rb_raise(rb_eArgError, "filename must be a string");

    Data_Get_Struct(self, rbpcap_t, rbp);

    memset(rbp->iface, 0, sizeof(rbp->iface));
    rbp->type = OFFLINE;

    rbp->pd = pcap_open_offline(
    	RSTRING(filename)->ptr,
    	eb
    );

    if(!rbp->pd)
    	rb_raise(rb_eRuntimeError, "%s", eb);

    return self;
}


static VALUE
rbpcap_open_offline_s(VALUE class, VALUE filename)
{
    VALUE iPcap = rb_funcall(rb_cPcap, rb_intern("new"), 0);

    return rbpcap_open_offline(iPcap, filename);
}

static VALUE
rbpcap_open_dead(VALUE self, VALUE linktype, VALUE snaplen)
{
    rbpcap_t *rbp;


    if(TYPE(linktype) != T_FIXNUM)
        rb_raise(rb_eArgError, "linktype must be a fixnum");
    if(TYPE(snaplen) != T_FIXNUM)
        rb_raise(rb_eArgError, "snaplen must be a fixnum");

    Data_Get_Struct(self, rbpcap_t, rbp);

    memset(rbp->iface, 0, sizeof(rbp->iface));
    rbp->type = OFFLINE;

    rbp->pd = pcap_open_dead(
        NUM2INT(linktype),
        NUM2INT(snaplen)
     );
	
    return self;
}

static VALUE
rbpcap_open_dead_s(VALUE class, VALUE linktype, VALUE snaplen)
{
    VALUE iPcap = rb_funcall(rb_cPcap, rb_intern("new"), 0);

    return rbpcap_open_dead(iPcap, linktype, snaplen);
}


static VALUE
rbpcap_dump_open(VALUE self, VALUE filename)
{
    rbpcap_t *rbp;

    if(TYPE(filename) != T_STRING)
       rb_raise(rb_eArgError, "filename must be a string");

    Data_Get_Struct(self, rbpcap_t, rbp);
    rbp->pdt = pcap_dump_open(
        rbp->pd,
        RSTRING(filename)->ptr
    );

    return self;
}

//not sure if this deviates too much from the way the rest of this class works?
static VALUE
rbpcap_dump(VALUE self, VALUE caplen, VALUE pktlen, VALUE packet)
{
    rbpcap_t *rbp;
    struct pcap_pkthdr pcap_hdr;

    if(TYPE(packet) != T_STRING)
        rb_raise(rb_eArgError, "packet data must be a string");
    if(TYPE(caplen) != T_FIXNUM)
        rb_raise(rb_eArgError, "caplen must be a fixnum");
    if(TYPE(pktlen) != T_FIXNUM)
        rb_raise(rb_eArgError, "pktlen must be a fixnum");

    Data_Get_Struct(self, rbpcap_t, rbp);
    
    gettimeofday(&pcap_hdr.ts, NULL);
    pcap_hdr.caplen = NUM2UINT(caplen);
    pcap_hdr.len = NUM2UINT(pktlen);

    pcap_dump(
        (u_char*)rbp->pdt,        
        &pcap_hdr,
        RSTRING(packet)->ptr
    );

    return self;
}

static VALUE
rbpcap_inject(VALUE self, VALUE payload)
{
    rbpcap_t *rbp;

    if(TYPE(payload) != T_STRING)
    	rb_raise(rb_eArgError, "payload must be a string");

    Data_Get_Struct(self, rbpcap_t, rbp);

	if(! rbpcap_ready(rbp)) return self; 
#if defined(WIN32)   
    /* WinPcap does not have a pcap_inject call we use pcap_sendpacket, if it suceedes 
     * we simply return the amount of packets request to inject, else we fail.
     */
    if(pcap_sendpacket(rbp->pd, RSTRING(payload)->ptr, RSTRING(payload)->len) != 0) {
    	rb_raise(rb_eRuntimeError, "%s", pcap_geterr(rbp->pd));
    }
    return INT2NUM(RSTRING(payload)->len);
#else
    return INT2NUM(pcap_inject(rbp->pd, RSTRING(payload)->ptr, RSTRING(payload)->len));
#endif
}


static void rbpcap_handler(rbpcapjob_t *job, struct pcap_pkthdr *hdr, u_char *pkt){
	job->pkt = pkt;
	job->hdr = *hdr;
}

static VALUE
rbpcap_next(VALUE self)
{
	rbpcap_t *rbp;
	rbpcapjob_t job;
	char eb[PCAP_ERRBUF_SIZE];
	int ret;	
	
	Data_Get_Struct(self, rbpcap_t, rbp);
	if(! rbpcap_ready(rbp)) return self; 
	pcap_setnonblock(rbp->pd, 1, eb);

	TRAP_BEG;

	ret = pcap_dispatch(rbp->pd, 1, (pcap_handler) rbpcap_handler, (u_char *)&job);
    
	TRAP_END;

	if(rbp->type == OFFLINE && ret <= 0) return Qnil;

	if(ret > 0 && job.hdr.caplen > 0)
		return rb_str_new(job.pkt, job.hdr.caplen);

	return Qnil;
}

static VALUE
rbpcap_capture(VALUE self)
{
    rbpcap_t *rbp;

    Data_Get_Struct(self, rbpcap_t, rbp);

	if(! rbpcap_ready(rbp)) return self; 
	
    for(;;) {

    	VALUE packet = rbpcap_next(self);

    	if(packet == Qnil && rbp->type == OFFLINE)
    		break;

    	if(packet != Qnil)
    		rb_yield(packet);
    }

    return self;
}


static VALUE
rbpcap_datalink(VALUE self)
{
    rbpcap_t *rbp;

    Data_Get_Struct(self, rbpcap_t, rbp);
	
	if(! rbpcap_ready(rbp)) return self;
	
    return INT2NUM(pcap_datalink(rbp->pd));
}

static VALUE
rbpcap_snapshot(VALUE self)
{
    rbpcap_t *rbp;

    Data_Get_Struct(self, rbpcap_t, rbp);

	if(! rbpcap_ready(rbp)) return self;
	
    return INT2NUM(pcap_snapshot(rbp->pd));
}

static VALUE
rbpcap_stats(VALUE self)
{
    rbpcap_t *rbp;
    struct pcap_stat stat;
    VALUE hash;
    
    Data_Get_Struct(self, rbpcap_t, rbp);

	if(! rbpcap_ready(rbp)) return self;
		
    if (pcap_stats(rbp->pd, &stat) == -1)
    	return Qnil;
    	
    hash = rb_hash_new();
    rb_hash_aset(hash, rb_str_new2("recv"), UINT2NUM(stat.ps_recv));
    rb_hash_aset(hash, rb_str_new2("drop"), UINT2NUM(stat.ps_drop));
    rb_hash_aset(hash, rb_str_new2("idrop"), UINT2NUM(stat.ps_ifdrop));
    return hash;
}

void
Init_pcaprub()
{
    // Pcap
    rb_cPcap = rb_define_class("Pcap", rb_cObject);
    rb_define_module_function(rb_cPcap, "version", rbpcap_s_version, 0);
    rb_define_module_function(rb_cPcap, "lookupdev", rbpcap_s_lookupdev, 0);
    rb_define_module_function(rb_cPcap, "lookupnet", rbpcap_s_lookupnet, 1);
		
    rb_define_const(rb_cPcap, "DLT_NULL",   INT2NUM(DLT_NULL));
    rb_define_const(rb_cPcap, "DLT_EN10MB", INT2NUM(DLT_EN10MB));
    rb_define_const(rb_cPcap, "DLT_EN3MB", INT2NUM(DLT_EN3MB));
    rb_define_const(rb_cPcap, "DLT_AX25", INT2NUM(DLT_AX25));
    rb_define_const(rb_cPcap, "DLT_PRONET", INT2NUM(DLT_PRONET));
    rb_define_const(rb_cPcap, "DLT_CHAOS", INT2NUM(DLT_CHAOS));
    rb_define_const(rb_cPcap, "DLT_IEEE802", INT2NUM(DLT_IEEE802));
    rb_define_const(rb_cPcap, "DLT_ARCNET", INT2NUM(DLT_ARCNET));
    rb_define_const(rb_cPcap, "DLT_SLIP", INT2NUM(DLT_SLIP));
    rb_define_const(rb_cPcap, "DLT_PPP", INT2NUM(DLT_PPP));
    rb_define_const(rb_cPcap, "DLT_FDDI", INT2NUM(DLT_FDDI));
    rb_define_const(rb_cPcap, "DLT_ATM_RFC1483", INT2NUM(DLT_ATM_RFC1483));
    rb_define_const(rb_cPcap, "DLT_RAW", INT2NUM(DLT_RAW));
    rb_define_const(rb_cPcap, "DLT_SLIP_BSDOS", INT2NUM(DLT_SLIP_BSDOS));
    rb_define_const(rb_cPcap, "DLT_PPP_BSDOS", INT2NUM(DLT_PPP_BSDOS));
    rb_define_const(rb_cPcap, "DLT_IEEE802_11", INT2NUM(DLT_IEEE802_11));
    rb_define_const(rb_cPcap, "DLT_IEEE802_11_RADIO", INT2NUM(DLT_IEEE802_11_RADIO));
    rb_define_const(rb_cPcap, "DLT_IEEE802_11_RADIO_AVS", INT2NUM(DLT_IEEE802_11_RADIO_AVS));
    rb_define_const(rb_cPcap, "DLT_LINUX_SLL", INT2NUM(DLT_LINUX_SLL));
    rb_define_const(rb_cPcap, "DLT_PRISM_HEADER", INT2NUM(DLT_PRISM_HEADER));
    rb_define_const(rb_cPcap, "DLT_AIRONET_HEADER", INT2NUM(DLT_AIRONET_HEADER));

    rb_define_singleton_method(rb_cPcap, "new", rbpcap_new_s, 0);

    rb_define_singleton_method(rb_cPcap, "open_live", rbpcap_open_live_s, 4);
    rb_define_singleton_method(rb_cPcap, "open_offline", rbpcap_open_offline_s, 1);
    rb_define_singleton_method(rb_cPcap, "open_dead", rbpcap_open_dead_s, 2);

    rb_define_method(rb_cPcap, "dump_open", rbpcap_dump_open, 1);
    rb_define_method(rb_cPcap, "dump", rbpcap_dump, 3);

    rb_define_method(rb_cPcap, "each", rbpcap_capture, 0);
    rb_define_method(rb_cPcap, "next", rbpcap_next, 0);
    rb_define_method(rb_cPcap, "setfilter", rbpcap_setfilter, 1);
    rb_define_method(rb_cPcap, "inject", rbpcap_inject, 1);
    rb_define_method(rb_cPcap, "datalink", rbpcap_datalink, 0);
    
    rb_define_method(rb_cPcap, "snapshot", rbpcap_snapshot, 0);
    rb_define_method(rb_cPcap, "snaplen", rbpcap_snapshot, 0);
    rb_define_method(rb_cPcap, "stats", rbpcap_stats, 0);
}
