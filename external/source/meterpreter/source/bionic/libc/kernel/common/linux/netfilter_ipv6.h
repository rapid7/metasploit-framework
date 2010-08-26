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
#ifndef __LINUX_IP6_NETFILTER_H
#define __LINUX_IP6_NETFILTER_H

#include <linux/netfilter.h>

#define NFC_IP6_SRC 0x0001

#define NFC_IP6_DST 0x0002

#define NFC_IP6_IF_IN 0x0004

#define NFC_IP6_IF_OUT 0x0008

#define NFC_IP6_TOS 0x0010

#define NFC_IP6_PROTO 0x0020

#define NFC_IP6_OPTIONS 0x0040

#define NFC_IP6_FRAG 0x0080

#define NFC_IP6_TCPFLAGS 0x0100

#define NFC_IP6_SRC_PT 0x0200

#define NFC_IP6_DST_PT 0x0400

#define NFC_IP6_PROTO_UNKNOWN 0x2000

#define NF_IP6_PRE_ROUTING 0

#define NF_IP6_LOCAL_IN 1

#define NF_IP6_FORWARD 2

#define NF_IP6_LOCAL_OUT 3

#define NF_IP6_POST_ROUTING 4
#define NF_IP6_NUMHOOKS 5

enum nf_ip6_hook_priorities {
 NF_IP6_PRI_FIRST = INT_MIN,
 NF_IP6_PRI_CONNTRACK_DEFRAG = -400,
 NF_IP6_PRI_SELINUX_FIRST = -225,
 NF_IP6_PRI_CONNTRACK = -200,
 NF_IP6_PRI_BRIDGE_SABOTAGE_FORWARD = -175,
 NF_IP6_PRI_MANGLE = -150,
 NF_IP6_PRI_NAT_DST = -100,
 NF_IP6_PRI_BRIDGE_SABOTAGE_LOCAL_OUT = -50,
 NF_IP6_PRI_FILTER = 0,
 NF_IP6_PRI_NAT_SRC = 100,
 NF_IP6_PRI_SELINUX_LAST = 225,
 NF_IP6_PRI_LAST = INT_MAX,
};

#endif
