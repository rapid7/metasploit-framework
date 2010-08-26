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
#ifndef _IPT_TTL_H
#define _IPT_TTL_H

enum {
 IPT_TTL_SET = 0,
 IPT_TTL_INC,
 IPT_TTL_DEC
};

#define IPT_TTL_MAXMODE IPT_TTL_DEC

struct ipt_TTL_info {
 u_int8_t mode;
 u_int8_t ttl;
};

#endif
