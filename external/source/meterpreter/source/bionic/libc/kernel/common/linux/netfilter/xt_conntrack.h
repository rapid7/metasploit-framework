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
#ifndef _XT_CONNTRACK_H
#define _XT_CONNTRACK_H

#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <linux/in.h>

#define XT_CONNTRACK_STATE_BIT(ctinfo) (1 << ((ctinfo)%IP_CT_IS_REPLY+1))
#define XT_CONNTRACK_STATE_INVALID (1 << 0)

#define XT_CONNTRACK_STATE_SNAT (1 << (IP_CT_NUMBER + 1))
#define XT_CONNTRACK_STATE_DNAT (1 << (IP_CT_NUMBER + 2))
#define XT_CONNTRACK_STATE_UNTRACKED (1 << (IP_CT_NUMBER + 3))

#define XT_CONNTRACK_STATE 0x01
#define XT_CONNTRACK_PROTO 0x02
#define XT_CONNTRACK_ORIGSRC 0x04
#define XT_CONNTRACK_ORIGDST 0x08
#define XT_CONNTRACK_REPLSRC 0x10
#define XT_CONNTRACK_REPLDST 0x20
#define XT_CONNTRACK_STATUS 0x40
#define XT_CONNTRACK_EXPIRES 0x80

struct ip_conntrack_old_tuple
{
 struct {
 __u32 ip;
 union {
 __u16 all;
 } u;
 } src;

 struct {
 __u32 ip;
 union {
 __u16 all;
 } u;

 __u16 protonum;
 } dst;
};

struct xt_conntrack_info
{
 unsigned int statemask, statusmask;

 struct ip_conntrack_old_tuple tuple[IP_CT_DIR_MAX];
 struct in_addr sipmsk[IP_CT_DIR_MAX], dipmsk[IP_CT_DIR_MAX];

 unsigned long expires_min, expires_max;

 u_int8_t flags;

 u_int8_t invflags;
};
#endif
