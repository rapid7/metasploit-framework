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
#ifndef _IPT_TCPMSS_H
#define _IPT_TCPMSS_H

struct ipt_tcpmss_info {
 u_int16_t mss;
};

#define IPT_TCPMSS_CLAMP_PMTU 0xffff

#endif
