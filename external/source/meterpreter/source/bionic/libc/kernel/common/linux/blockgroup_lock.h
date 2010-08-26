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
#ifndef _LINUX_BLOCKGROUP_LOCK_H
#define _LINUX_BLOCKGROUP_LOCK_H

#include <linux/spinlock.h>
#include <linux/cache.h>

#define NR_BG_LOCKS 1

struct bgl_lock {
 spinlock_t lock;
} ____cacheline_aligned_in_smp;

struct blockgroup_lock {
 struct bgl_lock locks[NR_BG_LOCKS];
};

#define sb_bgl_lock(sb, block_group)   (&(sb)->s_blockgroup_lock.locks[(block_group) & (NR_BG_LOCKS-1)].lock)
#endif
