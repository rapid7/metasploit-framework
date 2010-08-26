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
#ifndef _XT_PHYSDEV_H
#define _XT_PHYSDEV_H

#define XT_PHYSDEV_OP_IN 0x01
#define XT_PHYSDEV_OP_OUT 0x02
#define XT_PHYSDEV_OP_BRIDGED 0x04
#define XT_PHYSDEV_OP_ISIN 0x08
#define XT_PHYSDEV_OP_ISOUT 0x10
#define XT_PHYSDEV_OP_MASK (0x20 - 1)

struct xt_physdev_info {
 char physindev[IFNAMSIZ];
 char in_mask[IFNAMSIZ];
 char physoutdev[IFNAMSIZ];
 char out_mask[IFNAMSIZ];
 u_int8_t invert;
 u_int8_t bitmask;
};

#endif
