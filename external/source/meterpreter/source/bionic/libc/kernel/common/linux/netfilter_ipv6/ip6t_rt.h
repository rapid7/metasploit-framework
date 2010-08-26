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
#ifndef _IP6T_RT_H
#define _IP6T_RT_H

#define IP6T_RT_HOPS 16

struct ip6t_rt
{
 u_int32_t rt_type;
 u_int32_t segsleft[2];
 u_int32_t hdrlen;
 u_int8_t flags;
 u_int8_t invflags;
 struct in6_addr addrs[IP6T_RT_HOPS];
 u_int8_t addrnr;
};

#define IP6T_RT_TYP 0x01
#define IP6T_RT_SGS 0x02
#define IP6T_RT_LEN 0x04
#define IP6T_RT_RES 0x08
#define IP6T_RT_FST_MASK 0x30
#define IP6T_RT_FST 0x10
#define IP6T_RT_FST_NSTRICT 0x20

#define IP6T_RT_INV_TYP 0x01  
#define IP6T_RT_INV_SGS 0x02  
#define IP6T_RT_INV_LEN 0x04  
#define IP6T_RT_INV_MASK 0x07  

#endif
