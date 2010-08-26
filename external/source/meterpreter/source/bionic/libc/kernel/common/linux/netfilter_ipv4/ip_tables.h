/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef _IPTABLES_H
#define _IPTABLES_H

#include <linux/compiler.h>
#include <linux/netfilter_ipv4.h>

#include <linux/netfilter/x_tables.h>

#define IPT_FUNCTION_MAXNAMELEN XT_FUNCTION_MAXNAMELEN
#define IPT_TABLE_MAXNAMELEN XT_FUNCTION_MAXNAMELEN
#define ipt_match xt_match
#define ipt_target xt_target
#define ipt_table xt_table
#define ipt_get_revision xt_get_revision

struct ipt_ip {

 struct in_addr src, dst;

 struct in_addr smsk, dmsk;
 char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
 unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];

 u_int16_t proto;

 u_int8_t flags;

 u_int8_t invflags;
};

#define ipt_entry_match xt_entry_match
#define ipt_entry_target xt_entry_target
#define ipt_standard_target xt_standard_target

#define ipt_counters xt_counters

#define IPT_F_FRAG 0x01  
#define IPT_F_GOTO 0x02  
#define IPT_F_MASK 0x03  

#define IPT_INV_VIA_IN 0x01  
#define IPT_INV_VIA_OUT 0x02  
#define IPT_INV_TOS 0x04  
#define IPT_INV_SRCIP 0x08  
#define IPT_INV_DSTIP 0x10  
#define IPT_INV_FRAG 0x20  
#define IPT_INV_PROTO XT_INV_PROTO
#define IPT_INV_MASK 0x7F  

struct ipt_entry
{
 struct ipt_ip ip;

 unsigned int nfcache;

 u_int16_t target_offset;

 u_int16_t next_offset;

 unsigned int comefrom;

 struct xt_counters counters;

 unsigned char elems[0];
};

#define IPT_BASE_CTL XT_BASE_CTL

#define IPT_SO_SET_REPLACE XT_SO_SET_REPLACE
#define IPT_SO_SET_ADD_COUNTERS XT_SO_SET_ADD_COUNTERS
#define IPT_SO_SET_MAX XT_SO_SET_MAX

#define IPT_SO_GET_INFO XT_SO_GET_INFO
#define IPT_SO_GET_ENTRIES XT_SO_GET_ENTRIES
#define IPT_SO_GET_REVISION_MATCH XT_SO_GET_REVISION_MATCH
#define IPT_SO_GET_REVISION_TARGET XT_SO_GET_REVISION_TARGET
#define IPT_SO_GET_MAX XT_SO_GET_REVISION_TARGET

#define IPT_CONTINUE XT_CONTINUE
#define IPT_RETURN XT_RETURN

#include <linux/netfilter/xt_tcpudp.h>
#define ipt_udp xt_udp
#define ipt_tcp xt_tcp

#define IPT_TCP_INV_SRCPT XT_TCP_INV_SRCPT
#define IPT_TCP_INV_DSTPT XT_TCP_INV_DSTPT
#define IPT_TCP_INV_FLAGS XT_TCP_INV_FLAGS
#define IPT_TCP_INV_OPTION XT_TCP_INV_OPTION
#define IPT_TCP_INV_MASK XT_TCP_INV_MASK

#define IPT_UDP_INV_SRCPT XT_UDP_INV_SRCPT
#define IPT_UDP_INV_DSTPT XT_UDP_INV_DSTPT
#define IPT_UDP_INV_MASK XT_UDP_INV_MASK

struct ipt_icmp
{
 u_int8_t type;
 u_int8_t code[2];
 u_int8_t invflags;
};

#define IPT_ICMP_INV 0x01  

struct ipt_getinfo
{

 char name[IPT_TABLE_MAXNAMELEN];

 unsigned int valid_hooks;

 unsigned int hook_entry[NF_IP_NUMHOOKS];

 unsigned int underflow[NF_IP_NUMHOOKS];

 unsigned int num_entries;

 unsigned int size;
};

struct ipt_replace
{

 char name[IPT_TABLE_MAXNAMELEN];

 unsigned int valid_hooks;

 unsigned int num_entries;

 unsigned int size;

 unsigned int hook_entry[NF_IP_NUMHOOKS];

 unsigned int underflow[NF_IP_NUMHOOKS];

 unsigned int num_counters;

 struct xt_counters __user *counters;

 struct ipt_entry entries[0];
};

#define ipt_counters_info xt_counters_info

struct ipt_get_entries
{

 char name[IPT_TABLE_MAXNAMELEN];

 unsigned int size;

 struct ipt_entry entrytable[0];
};

#define IPT_STANDARD_TARGET XT_STANDARD_TARGET

#define IPT_ERROR_TARGET XT_ERROR_TARGET

static __inline__ struct ipt_entry_target *
ipt_get_target(struct ipt_entry *e)
{
 return (void *)e + e->target_offset;
}

#define IPT_MATCH_ITERATE(e, fn, args...)  ({   unsigned int __i;   int __ret = 0;   struct ipt_entry_match *__match;     for (__i = sizeof(struct ipt_entry);   __i < (e)->target_offset;   __i += __match->u.match_size) {   __match = (void *)(e) + __i;     __ret = fn(__match , ## args);   if (__ret != 0)   break;   }   __ret;  })

#define IPT_ENTRY_ITERATE(entries, size, fn, args...)  ({   unsigned int __i;   int __ret = 0;   struct ipt_entry *__entry;     for (__i = 0; __i < (size); __i += __entry->next_offset) {   __entry = (void *)(entries) + __i;     __ret = fn(__entry , ## args);   if (__ret != 0)   break;   }   __ret;  })

#endif
