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
#ifndef _IP6T_AH_H
#define _IP6T_AH_H

struct ip6t_ah
{
 u_int32_t spis[2];
 u_int32_t hdrlen;
 u_int8_t hdrres;
 u_int8_t invflags;
};

#define IP6T_AH_SPI 0x01
#define IP6T_AH_LEN 0x02
#define IP6T_AH_RES 0x04

#define IP6T_AH_INV_SPI 0x01  
#define IP6T_AH_INV_LEN 0x02  
#define IP6T_AH_INV_MASK 0x03  

#endif
