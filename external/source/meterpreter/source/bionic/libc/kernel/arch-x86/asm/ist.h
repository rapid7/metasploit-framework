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
#ifndef _ASM_IST_H
#define _ASM_IST_H

#include <linux/types.h>

struct ist_info {
 __u32 signature;
 __u32 command;
 __u32 event;
 __u32 perf_level;
};

#endif
