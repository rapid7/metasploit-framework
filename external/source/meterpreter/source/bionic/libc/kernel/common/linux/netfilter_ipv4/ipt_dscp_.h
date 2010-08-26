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
#ifndef _IPT_DSCP_H
#define _IPT_DSCP_H

#define IPT_DSCP_MASK 0xfc  
#define IPT_DSCP_SHIFT 2
#define IPT_DSCP_MAX 0x3f  

struct ipt_dscp_info {
 u_int8_t dscp;
 u_int8_t invert;
};

#endif
