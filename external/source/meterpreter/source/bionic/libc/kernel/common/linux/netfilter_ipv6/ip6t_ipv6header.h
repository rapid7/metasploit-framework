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
#ifndef __IPV6HEADER_H
#define __IPV6HEADER_H

struct ip6t_ipv6header_info
{
 u_int8_t matchflags;
 u_int8_t invflags;
 u_int8_t modeflag;
};

#define MASK_HOPOPTS 128
#define MASK_DSTOPTS 64
#define MASK_ROUTING 32
#define MASK_FRAGMENT 16
#define MASK_AH 8
#define MASK_ESP 4
#define MASK_NONE 2
#define MASK_PROTO 1

#endif
