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
#ifndef _IP6T_OPTS_H
#define _IP6T_OPTS_H

#define IP6T_OPTS_OPTSNR 16

struct ip6t_opts
{
 u_int32_t hdrlen;
 u_int8_t flags;
 u_int8_t invflags;
 u_int16_t opts[IP6T_OPTS_OPTSNR];
 u_int8_t optsnr;
};

#define IP6T_OPTS_LEN 0x01
#define IP6T_OPTS_OPTS 0x02
#define IP6T_OPTS_NSTRICT 0x04

#define IP6T_OPTS_INV_LEN 0x01  
#define IP6T_OPTS_INV_MASK 0x01  

#endif
