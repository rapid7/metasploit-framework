#include "ruby.h"

#ifndef RUBY_19
#include "rubysig.h"
#endif

#include "netifaces.h"

#include <pcap.h>

#if !defined(WIN32)
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <sys/time.h>
#endif

#if !defined(DLT_IEEE802_11_RADIO_AVS)
#define DLT_IEEE802_11_RADIO_AVS 163
#endif

#if !defined(DLT_LINUX_SLL)
#define DLT_LINUX_SLL 113
#endif

#if !defined(DLT_PRISM_HEADER)
#define DLT_PRISM_HEADER 119
#endif

#if !defined(DLT_AIRONET_HEADER)
#define DLT_AIRONET_HEADER 120
#endif

#if !defined(PCAP_NETMASK_UNKNOWN)
/*
 * Value to pass to pcap_compile() as the netmask if you don't know what
 * the netmask is.
 */
#define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

static VALUE rb_cPcap;

#define PCAPRUB_VERSION "0.9-dev"

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
    unsigned char *pkt;
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
rbpcap_s_lookupaddrs(VALUE self,VALUE dev)
{
    char *ldev = NULL;
    pcap_addr_t *addresses, *a = NULL;
    char eb[PCAP_ERRBUF_SIZE];
    VALUE ret_dev;  /* device string to return */   
    pcap_if_t *alldevs;
    pcap_if_t *d;
    VALUE list;

    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs(&alldevs,eb) == -1) {
        rb_raise(rb_eRuntimeError,"%s",eb);
    }

    /* Find the first interface with an address and not loopback */
    for(d = alldevs; d != NULL; d= d->next)  {
        if(strcmp(d->name,StringValuePtr(dev)) == 0 && d->addresses && !(d->flags & PCAP_IF_LOOPBACK)) {
            ldev=d->name;
	    addresses=d->addresses;
            break;
        }
    }
    
    if (ldev == NULL) {
        rb_raise(rb_eRuntimeError,"%s","No valid interfaces found.\n");
    }

    list = rb_ary_new();
    for(a = addresses; a != NULL; a= a->next)  {
      switch(a->addr->sa_family)
      {
         case AF_INET:
             if (a->addr)
                 rb_ary_push(list,  rb_str_new2(inet_ntoa((((struct sockaddr_in *)a->addr)->sin_addr))));
             break;
	/* Don't like the __MINGW32__ comment  for the moment need some testing ...
	  case AF_INET6:
	  #ifndef __MINGW32__ // Cygnus doesn't have IPv6 
             if (a->addr)
             printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
	  #endif
	    break;
	*/
	  default:
	      break;
      }
    }
    pcap_freealldevs(alldevs); 
    return(list);
}

static VALUE
rbpcap_s_lookupnet(VALUE self, VALUE dev)
{
    bpf_u_int32 net, mask, m;
    struct in_addr addr;
    char eb[PCAP_ERRBUF_SIZE];
	VALUE list;
	
    Check_Type(dev, T_STRING);
    if (pcap_lookupnet(StringValuePtr(dev), &net, &mask, eb) == -1) {
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

static void rbpcap_free(rbpcap_t *rbp) {
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
    self = Data_Make_Struct(class, rbpcap_t, 0, rbpcap_free, rbp);
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

    if(pcap_compile(rbp->pd, &bpf, RSTRING_PTR(filter), 0, mask) < 0)
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
    strncpy(rbp->iface, RSTRING_PTR(iface), sizeof(rbp->iface) - 1);

	
    if(rbp->pd) {
        pcap_close(rbp->pd);	
    }
	
    rbp->pd = pcap_open_live(
    	RSTRING_PTR(iface),
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
    	RSTRING_PTR(filename),
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
        RSTRING_PTR(filename)
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
        (unsigned char *)RSTRING_PTR(packet)
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
    if(pcap_sendpacket(rbp->pd, RSTRING_PTR(payload), RSTRING_LEN(payload)) != 0) {
    	rb_raise(rb_eRuntimeError, "%s", pcap_geterr(rbp->pd));
    }
    return INT2NUM(RSTRING_LEN(payload));
#else
    return INT2NUM(pcap_inject(rbp->pd, RSTRING_PTR(payload), RSTRING_LEN(payload)));
#endif
}


static void rbpcap_handler(rbpcapjob_t *job, struct pcap_pkthdr *hdr, u_char *pkt){
	job->pkt = (unsigned char *)pkt;
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

#ifndef RUBY_19
	TRAP_BEG;
#endif
	ret = pcap_dispatch(rbp->pd, 1, (pcap_handler) rbpcap_handler, (u_char *)&job);
#ifndef RUBY_19
	TRAP_END;
#endif

	if(rbp->type == OFFLINE && ret <= 0) return Qnil;

	if(ret > 0 && job.hdr.caplen > 0)
             return rb_str_new((char *) job.pkt, job.hdr.caplen);

	return Qnil;
}

static VALUE
rbpcap_capture(VALUE self)
{
    rbpcap_t *rbp;
	int fno = -1;
	
    Data_Get_Struct(self, rbpcap_t, rbp);

	if(! rbpcap_ready(rbp)) return self; 
	
#if !defined(WIN32)
	fno = pcap_get_selectable_fd(rbp->pd);
#else
	fno = pcap_fileno(rbp->pd);
#endif

    for(;;) {
    	VALUE packet = rbpcap_next(self);
    	if(packet == Qnil && rbp->type == OFFLINE) break;
		packet == Qnil ? rb_thread_wait_fd(fno) : rb_yield(packet);
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
	rb_define_module_function(rb_cPcap, "lookupaddrs", rbpcap_s_lookupaddrs, 1);
		
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
	rb_define_singleton_method(rb_cPcap, "dump_open", rbpcap_dump_open, 1);
	
	rb_define_method(rb_cPcap, "dump", rbpcap_dump, 3);

	rb_define_method(rb_cPcap, "each", rbpcap_capture, 0);
	rb_define_method(rb_cPcap, "next", rbpcap_next, 0);
	rb_define_method(rb_cPcap, "setfilter", rbpcap_setfilter, 1);
	rb_define_method(rb_cPcap, "inject", rbpcap_inject, 1);
	rb_define_method(rb_cPcap, "datalink", rbpcap_datalink, 0);
    
	rb_define_method(rb_cPcap, "snapshot", rbpcap_snapshot, 0);
	rb_define_method(rb_cPcap, "snaplen", rbpcap_snapshot, 0);
	rb_define_method(rb_cPcap, "stats", rbpcap_stats, 0);


	//Netifaces
	rb_define_module_function(rb_cPcap, "interfaces", rbnetifaces_s_interfaces, 0);
	rb_define_module_function(rb_cPcap, "addresses", rbnetifaces_s_addresses, 1);
	rb_define_module_function(rb_cPcap, "interface_info", rbnetifaces_s_interface_info, 1);

	//constants
	// Address families (auto-detect using #ifdef) 

#ifdef AF_INET
	rb_define_const(rb_cPcap, "AF_INET", INT2NUM(AF_INET));
#endif
#ifdef AF_INET6
	rb_define_const(rb_cPcap, "AF_INET6", INT2NUM(AF_INET6));
#endif
#ifdef AF_UNSPEC  
	rb_define_const(rb_cPcap, "AF_UNSPEC", INT2NUM(AF_UNSPEC));
#endif
#ifdef AF_UNIX
	rb_define_const(rb_cPcap, "AF_UNIX", INT2NUM(AF_UNIX));
#endif
#ifdef AF_FILE
	rb_define_const(rb_cPcap, "AF_FILE", INT2NUM(AF_FILE));
#endif

#ifdef AF_AX25
	rb_define_const(rb_cPcap, "AF_AX25", INT2NUM(AF_AX25));
#endif
#ifdef AF_IMPLINK  
	rb_define_const(rb_cPcap, "AF_IMPLINK", INT2NUM(AF_IMPLINK));
#endif
#ifdef AF_PUP  
	rb_define_const(rb_cPcap, "AF_PUP", INT2NUM(AF_PUP));
#endif
#ifdef AF_CHAOS
	rb_define_const(rb_cPcap, "AF_CHAOS", INT2NUM(AF_CHAOS));
#endif
#ifdef AF_NS
	rb_define_const(rb_cPcap, "AF_NS", INT2NUM(AF_NS));
#endif
#ifdef AF_ISO
	rb_define_const(rb_cPcap, "AF_ISO", INT2NUM(AF_ISO));
#endif
#ifdef AF_ECMA
	rb_define_const(rb_cPcap, "AF_ECMA", INT2NUM(AF_ECMA));
#endif
#ifdef AF_DATAKIT
	rb_define_const(rb_cPcap, "AF_DATAKIT", INT2NUM(AF_DATAKIT));
#endif
#ifdef AF_CCITT
	rb_define_const(rb_cPcap, "AF_CCITT", INT2NUM(AF_CCITT));
#endif
#ifdef AF_SNA
	rb_define_const(rb_cPcap, "AF_SNA", INT2NUM(AF_SNA));
#endif
#ifdef AF_DECnet
	rb_define_const(rb_cPcap, "AF_DECnet", INT2NUM(AF_DECnet));
#endif
#ifdef AF_DLI
	rb_define_const(rb_cPcap, "AF_DLI", INT2NUM(AF_DLI));
#endif
#ifdef AF_LAT
	rb_define_const(rb_cPcap, "AF_LAT", INT2NUM(AF_LAT));
#endif
#ifdef AF_HYLINK
	rb_define_const(rb_cPcap, "AF_HYLINK", INT2NUM(AF_HYLINK));
#endif
#ifdef AF_APPLETALK
	rb_define_const(rb_cPcap, "AF_APPLETALK", INT2NUM(AF_APPLETALK));
#endif
#ifdef AF_ROUTE
	rb_define_const(rb_cPcap, "AF_ROUTE", INT2NUM(AF_ROUTE));
#endif
#ifdef AF_LINK
	rb_define_const(rb_cPcap, "AF_LINK", INT2NUM(AF_LINK));
#endif
#ifdef AF_PACKET
	rb_define_const(rb_cPcap, "AF_PACKET", INT2NUM(AF_PACKET));
#endif
#ifdef AF_COIP
	rb_define_const(rb_cPcap, "AF_COIP", INT2NUM(AF_COIP));
#endif
#ifdef AF_CNT
	rb_define_const(rb_cPcap, "AF_CNT", INT2NUM(AF_CNT));
#endif
#ifdef AF_IPX
	rb_define_const(rb_cPcap, "AF_IPX", INT2NUM(AF_IPX));
#endif
#ifdef AF_SIP
	rb_define_const(rb_cPcap, "AF_SIP", INT2NUM(AF_SIP));
#endif
#ifdef AF_NDRV
	rb_define_const(rb_cPcap, "AF_NDRV", INT2NUM(AF_NDRV));
#endif
#ifdef AF_ISDN
	rb_define_const(rb_cPcap, "AF_ISDN", INT2NUM(AF_ISDN));
#endif
#ifdef AF_NATM
	rb_define_const(rb_cPcap, "AF_NATM", INT2NUM(AF_NATM));
#endif
#ifdef AF_SYSTEM
	rb_define_const(rb_cPcap, "AF_SYSTEM", INT2NUM(AF_SYSTEM));
#endif
#ifdef AF_NETBIOS
	rb_define_const(rb_cPcap, "AF_NETBIOS", INT2NUM(AF_NETBIOS));
#endif
#ifdef AF_NETBEUI
	rb_define_const(rb_cPcap, "AF_NETBEUI", INT2NUM(AF_NETBEUI));
#endif
#ifdef AF_PPP
	rb_define_const(rb_cPcap, "AF_PPP", INT2NUM(AF_PPP));
#endif
#ifdef AF_ATM
	rb_define_const(rb_cPcap, "AF_ATM", INT2NUM(AF_ATM));
#endif
#ifdef AF_ATMPVC
	rb_define_const(rb_cPcap, "AF_ATMPVC", INT2NUM(AF_ATMPVC));
#endif
#ifdef AF_ATMSVC
	rb_define_const(rb_cPcap, "AF_ATMSVC", INT2NUM(AF_ATMSVC));
#endif
#ifdef AF_NETGRAPH
	rb_define_const(rb_cPcap, "AF_NETGRAPH", INT2NUM(AF_NETGRAPH));
#endif
#ifdef AF_VOICEVIEW
	rb_define_const(rb_cPcap, "AF_VOICEVIEW", INT2NUM(AF_VOICEVIEW));
#endif
#ifdef AF_FIREFOX
	rb_define_const(rb_cPcap, "AF_FIREFOX", INT2NUM(AF_FIREFOX));
#endif
#ifdef AF_UNKNOWN1
	rb_define_const(rb_cPcap, "AF_UNKNOWN1", INT2NUM(AF_UNKNOWN1));
#endif
#ifdef AF_BAN
	rb_define_const(rb_cPcap, "AF_BAN", INT2NUM(AF_BAN));
#endif
#ifdef AF_CLUSTER
	rb_define_const(rb_cPcap, "AF_CLUSTER", INT2NUM(AF_CLUSTER));
#endif
#ifdef AF_12844
	rb_define_const(rb_cPcap, "AF_12844", INT2NUM(AF_12844));
#endif
#ifdef AF_IRDA
	rb_define_const(rb_cPcap, "AF_IRDA", INT2NUM(AF_IRDA));
#endif
#ifdef AF_NETDES
	rb_define_const(rb_cPcap, "AF_NETDES", INT2NUM(AF_NETDES));
#endif
#ifdef AF_NETROM
	rb_define_const(rb_cPcap, "AF_NETROM", INT2NUM(AF_NETROM));
#endif
#ifdef AF_BRIDGE
	rb_define_const(rb_cPcap, "AF_BRIDGE", INT2NUM(AF_BRIDGE));
#endif
#ifdef AF_X25
	rb_define_const(rb_cPcap, "AF_X25", INT2NUM(AF_X25));
#endif
#ifdef AF_ROSE
	rb_define_const(rb_cPcap, "AF_ROSE", INT2NUM(AF_ROSE));
#endif
#ifdef AF_SECURITY
	rb_define_const(rb_cPcap, "AF_SECURITY", INT2NUM(AF_SECURITY));
#endif
#ifdef AF_KEY
	rb_define_const(rb_cPcap, "AF_KEY", INT2NUM(AF_KEY));
#endif
#ifdef AF_NETLINK
	rb_define_const(rb_cPcap, "AF_NETLINK", INT2NUM(AF_NETLINK));
#endif
#ifdef AF_ASH
	rb_define_const(rb_cPcap, "AF_ASH", INT2NUM(AF_ASH));
#endif
#ifdef AF_ECONET
	rb_define_const(rb_cPcap, "AF_ECONET", INT2NUM(AF_ECONET));
#endif
#ifdef AF_PPPOX
	rb_define_const(rb_cPcap, "AF_PPPOX", INT2NUM(AF_PPPOX));
#endif
#ifdef AF_WANPIPE
	rb_define_const(rb_cPcap, "AF_WANPIPE", INT2NUM(AF_WANPIPE));
#endif
#ifdef AF_BLUETOOTH
	rb_define_const(rb_cPcap, "AF_BLUETOOTH", INT2NUM(AF_BLUETOOTH));
#endif

}
