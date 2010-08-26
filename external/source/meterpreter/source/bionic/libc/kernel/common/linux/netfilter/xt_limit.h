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
#ifndef _XT_RATE_H
#define _XT_RATE_H

#define XT_LIMIT_SCALE 10000

struct xt_rateinfo {
 u_int32_t avg;
 u_int32_t burst;

 unsigned long prev;
 u_int32_t credit;
 u_int32_t credit_cap, cost;

 struct xt_rateinfo *master;
};
#endif
