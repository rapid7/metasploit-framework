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
#ifndef _IPT_AH_H
#define _IPT_AH_H

struct ipt_ah
{
 u_int32_t spis[2];
 u_int8_t invflags;
};

#define IPT_AH_INV_SPI 0x01  
#define IPT_AH_INV_MASK 0x01  

#endif
