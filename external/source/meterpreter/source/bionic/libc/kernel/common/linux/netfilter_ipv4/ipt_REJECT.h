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
#ifndef _IPT_REJECT_H
#define _IPT_REJECT_H

enum ipt_reject_with {
 IPT_ICMP_NET_UNREACHABLE,
 IPT_ICMP_HOST_UNREACHABLE,
 IPT_ICMP_PROT_UNREACHABLE,
 IPT_ICMP_PORT_UNREACHABLE,
 IPT_ICMP_ECHOREPLY,
 IPT_ICMP_NET_PROHIBITED,
 IPT_ICMP_HOST_PROHIBITED,
 IPT_TCP_RESET,
 IPT_ICMP_ADMIN_PROHIBITED
};

struct ipt_reject_info {
 enum ipt_reject_with with;
};

#endif
