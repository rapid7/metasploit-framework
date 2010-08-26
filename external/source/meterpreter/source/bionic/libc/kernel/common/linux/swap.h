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
#ifndef _LINUX_SWAP_H
#define _LINUX_SWAP_H

#include <linux/spinlock.h>
#include <linux/linkage.h>
#include <linux/mmzone.h>
#include <linux/list.h>
#include <linux/sched.h>

#include <asm/atomic.h>
#include <asm/page.h>

#define SWAP_FLAG_PREFER 0x8000  
#define SWAP_FLAG_PRIO_MASK 0x7fff
#define SWAP_FLAG_PRIO_SHIFT 0

#define MAX_SWAPFILES_SHIFT 5
#define MAX_SWAPFILES (1 << MAX_SWAPFILES_SHIFT)

typedef struct {
 unsigned long val;
} swp_entry_t;

struct reclaim_state {
 unsigned long reclaimed_slab;
};

#endif
