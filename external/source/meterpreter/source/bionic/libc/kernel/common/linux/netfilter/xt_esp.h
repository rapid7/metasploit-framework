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
#ifndef _XT_ESP_H
#define _XT_ESP_H

struct xt_esp
{
 u_int32_t spis[2];
 u_int8_t invflags;
};

#define XT_ESP_INV_SPI 0x01  
#define XT_ESP_INV_MASK 0x01  

#endif
