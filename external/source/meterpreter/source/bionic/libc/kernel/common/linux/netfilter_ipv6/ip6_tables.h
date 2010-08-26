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
#ifndef _IP6_TABLES_H
#define _IP6_TABLES_H

#include <linux/compiler.h>
#include <linux/netfilter_ipv6.h>

#include <linux/netfilter/x_tables.h>

#define IP6T_FUNCTION_MAXNAMELEN XT_FUNCTION_MAXNAMELEN
#define IP6T_TABLE_MAXNAMELEN XT_TABLE_MAXNAMELEN

#define ip6t_match xt_match
#define ip6t_target xt_target
#define ip6t_table xt_table
#define ip6t_get_revision xt_get_revision

struct ip6t_ip6 {

 struct in6_addr src, dst;

 struct in6_addr smsk, dmsk;
 char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
 unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];

 u_int16_t proto;

 u_int8_t tos;

 u_int8_t flags;

 u_int8_t invflags;
};

#define ip6t_entry_match xt_entry_match
#define ip6t_entry_target xt_entry_target
#define ip6t_standard_target xt_standard_target

#define ip6t_counters xt_counters

#define IP6T_F_PROTO 0x01  
#define IP6T_F_TOS 0x02  
#define IP6T_F_GOTO 0x04  
#define IP6T_F_MASK 0x07  

#define IP6T_INV_VIA_IN 0x01  
#define IP6T_INV_VIA_OUT 0x02  
#define IP6T_INV_TOS 0x04  
#define IP6T_INV_SRCIP 0x08  
#define IP6T_INV_DSTIP 0x10  
#define IP6T_INV_FRAG 0x20  
#define IP6T_INV_PROTO XT_INV_PROTO
#define IP6T_INV_MASK 0x7F  

struct ip6t_entry
{
 struct ip6t_ip6 ipv6;

 unsigned int nfcache;

 u_int16_t target_offset;

 u_int16_t next_offset;

 unsigned int comefrom;

 struct xt_counters counters;

 unsigned char elems[0];
};

#define IP6T_BASE_CTL XT_BASE_CTL

#define IP6T_SO_SET_REPLACE XT_SO_SET_REPLACE
#define IP6T_SO_SET_ADD_COUNTERS XT_SO_SET_ADD_COUNTERS
#define IP6T_SO_SET_MAX XT_SO_SET_MAX

#define IP6T_SO_GET_INFO XT_SO_GET_INFO
#define IP6T_SO_GET_ENTRIES XT_SO_GET_ENTRIES
#define IP6T_SO_GET_REVISION_MATCH XT_SO_GET_REVISION_MATCH
#define IP6T_SO_GET_REVISION_TARGET XT_SO_GET_REVISION_TARGET
#define IP6T_SO_GET_MAX XT_SO_GET_REVISION_TARGET

#define IP6T_CONTINUE XT_CONTINUE

#define IP6T_RETURN XT_RETURN

#include <linux/netfilter/xt_tcpudp.h>

#define ip6t_tcp xt_tcp
#define ip6t_udp xt_udp

#define IP6T_TCP_INV_SRCPT XT_TCP_INV_SRCPT
#define IP6T_TCP_INV_DSTPT XT_TCP_INV_DSTPT
#define IP6T_TCP_INV_FLAGS XT_TCP_INV_FLAGS
#define IP6T_TCP_INV_OPTION XT_TCP_INV_OPTION
#define IP6T_TCP_INV_MASK XT_TCP_INV_MASK

#define IP6T_UDP_INV_SRCPT XT_UDP_INV_SRCPT
#define IP6T_UDP_INV_DSTPT XT_UDP_INV_DSTPT
#define IP6T_UDP_INV_MASK XT_UDP_INV_MASK

struct ip6t_icmp
{
 u_int8_t type;
 u_int8_t code[2];
 u_int8_t invflags;
};

#define IP6T_ICMP_INV 0x01  

struct ip6t_getinfo
{

 char name[IP6T_TABLE_MAXNAMELEN];

 unsigned int valid_hooks;

 unsigned int hook_entry[NF_IP6_NUMHOOKS];

 unsigned int underflow[NF_IP6_NUMHOOKS];

 unsigned int num_entries;

 unsigned int size;
};

struct ip6t_replace
{

 char name[IP6T_TABLE_MAXNAMELEN];

 unsigned int valid_hooks;

 unsigned int num_entries;

 unsigned int size;

 unsigned int hook_entry[NF_IP6_NUMHOOKS];

 unsigned int underflow[NF_IP6_NUMHOOKS];

 unsigned int num_counters;

 struct xt_counters __user *counters;

 struct ip6t_entry entries[0];
};

#define ip6t_counters_info xt_counters_info

struct ip6t_get_entries
{

 char name[IP6T_TABLE_MAXNAMELEN];

 unsigned int size;

 struct ip6t_entry entrytable[0];
};

#define IP6T_STANDARD_TARGET XT_STANDARD_TARGET

#define IP6T_ERROR_TARGET XT_ERROR_TARGET

static __inline__ struct ip6t_entry_target *
ip6t_get_target(struct ip6t_entry *e)
{
 return (void *)e + e->target_offset;
}

#define IP6T_MATCH_ITERATE(e, fn, args...)  ({   unsigned int __i;   int __ret = 0;   struct ip6t_entry_match *__m;     for (__i = sizeof(struct ip6t_entry);   __i < (e)->target_offset;   __i += __m->u.match_size) {   __m = (void *)(e) + __i;     __ret = fn(__m , ## args);   if (__ret != 0)   break;   }   __ret;  })

#define IP6T_ENTRY_ITERATE(entries, size, fn, args...)  ({   unsigned int __i;   int __ret = 0;   struct ip6t_entry *__e;     for (__i = 0; __i < (size); __i += __e->next_offset) {   __e = (void *)(entries) + __i;     __ret = fn(__e , ## args);   if (__ret != 0)   break;   }   __ret;  })

#endif

