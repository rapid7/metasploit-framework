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
#ifndef __ASM_SH_HEARTBEAT_H
#define __ASM_SH_HEARTBEAT_H

#include <linux/timer.h>

#define HEARTBEAT_INVERTED (1 << 0)

struct heartbeat_data {
 void __iomem *base;
 unsigned char *bit_pos;
 unsigned int nr_bits;
 struct timer_list timer;
 unsigned int regsize;
 unsigned long flags;
};

#endif
