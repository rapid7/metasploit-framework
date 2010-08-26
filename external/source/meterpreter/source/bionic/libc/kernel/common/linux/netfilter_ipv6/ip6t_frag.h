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
#ifndef _IP6T_FRAG_H
#define _IP6T_FRAG_H

struct ip6t_frag
{
 u_int32_t ids[2];
 u_int32_t hdrlen;
 u_int8_t flags;
 u_int8_t invflags;
};

#define IP6T_FRAG_IDS 0x01
#define IP6T_FRAG_LEN 0x02
#define IP6T_FRAG_RES 0x04
#define IP6T_FRAG_FST 0x08
#define IP6T_FRAG_MF 0x10
#define IP6T_FRAG_NMF 0x20

#define IP6T_FRAG_INV_IDS 0x01  
#define IP6T_FRAG_INV_LEN 0x02  
#define IP6T_FRAG_INV_MASK 0x03  

#endif
