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
#ifndef _IPT_IPRANGE_H
#define _IPT_IPRANGE_H

#define IPRANGE_SRC 0x01  
#define IPRANGE_DST 0x02  
#define IPRANGE_SRC_INV 0x10  
#define IPRANGE_DST_INV 0x20  

struct ipt_iprange {

 u_int32_t min_ip, max_ip;
};

struct ipt_iprange_info
{
 struct ipt_iprange src;
 struct ipt_iprange dst;

 u_int8_t flags;
};

#endif
