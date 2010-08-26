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
#ifndef _IP_NAT_H
#define _IP_NAT_H
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_conntrack_tuple.h>

#define IP_NAT_MAPPING_TYPE_MAX_NAMELEN 16

enum ip_nat_manip_type
{
 IP_NAT_MANIP_SRC,
 IP_NAT_MANIP_DST
};

#define HOOK2MANIP(hooknum) ((hooknum) != NF_IP_POST_ROUTING && (hooknum) != NF_IP_LOCAL_IN)

#define IP_NAT_RANGE_MAP_IPS 1
#define IP_NAT_RANGE_PROTO_SPECIFIED 2

struct ip_nat_seq {

 u_int32_t correction_pos;

 int16_t offset_before, offset_after;
};

struct ip_nat_range
{

 unsigned int flags;

 u_int32_t min_ip, max_ip;

 union ip_conntrack_manip_proto min, max;
};

struct ip_nat_multi_range_compat
{
 unsigned int rangesize;

 struct ip_nat_range range[1];
};

#define ip_nat_multi_range ip_nat_multi_range_compat
#endif
