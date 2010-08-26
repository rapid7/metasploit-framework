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
#ifndef __LINUX_SPINLOCK_TYPES_H
#define __LINUX_SPINLOCK_TYPES_H

#include <linux/lockdep.h>

#include <linux/spinlock_types_up.h>

typedef struct {
 raw_spinlock_t raw_lock;
} spinlock_t;

#define SPINLOCK_MAGIC 0xdead4ead

typedef struct {
 raw_rwlock_t raw_lock;
} rwlock_t;

#define RWLOCK_MAGIC 0xdeaf1eed

#define SPINLOCK_OWNER_INIT ((void *)-1L)

#define SPIN_DEP_MAP_INIT(lockname)

#define RW_DEP_MAP_INIT(lockname)

#define __SPIN_LOCK_UNLOCKED(lockname)   (spinlock_t) { .raw_lock = __RAW_SPIN_LOCK_UNLOCKED,   SPIN_DEP_MAP_INIT(lockname) }
#define __RW_LOCK_UNLOCKED(lockname)   (rwlock_t) { .raw_lock = __RAW_RW_LOCK_UNLOCKED,   RW_DEP_MAP_INIT(lockname) }

#define SPIN_LOCK_UNLOCKED __SPIN_LOCK_UNLOCKED(old_style_spin_init)
#define RW_LOCK_UNLOCKED __RW_LOCK_UNLOCKED(old_style_rw_init)

#define DEFINE_SPINLOCK(x) spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
#define DEFINE_RWLOCK(x) rwlock_t x = __RW_LOCK_UNLOCKED(x)

#endif
