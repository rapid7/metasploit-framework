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
#ifndef _XT_TCPUDP_H
#define _XT_TCPUDP_H

struct xt_tcp
{
 u_int16_t spts[2];
 u_int16_t dpts[2];
 u_int8_t option;
 u_int8_t flg_mask;
 u_int8_t flg_cmp;
 u_int8_t invflags;
};

#define XT_TCP_INV_SRCPT 0x01  
#define XT_TCP_INV_DSTPT 0x02  
#define XT_TCP_INV_FLAGS 0x04  
#define XT_TCP_INV_OPTION 0x08  
#define XT_TCP_INV_MASK 0x0F  

struct xt_udp
{
 u_int16_t spts[2];
 u_int16_t dpts[2];
 u_int8_t invflags;
};

#define XT_UDP_INV_SRCPT 0x01  
#define XT_UDP_INV_DSTPT 0x02  
#define XT_UDP_INV_MASK 0x03  

#endif
