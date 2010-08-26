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
#ifndef _XT_TCPMSS_MATCH_H
#define _XT_TCPMSS_MATCH_H

struct xt_tcpmss_match_info {
 u_int16_t mss_min, mss_max;
 u_int8_t invert;
};

#endif
