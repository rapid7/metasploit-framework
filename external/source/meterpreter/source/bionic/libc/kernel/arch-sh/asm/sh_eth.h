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
#ifndef __ASM_SH_ETH_H__
#define __ASM_SH_ETH_H__

enum {EDMAC_LITTLE_ENDIAN, EDMAC_BIG_ENDIAN};

struct sh_eth_plat_data {
 int phy;
 int edmac_endian;
};

#endif
