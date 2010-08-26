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
#ifndef __ASM_ARM_SEMAPHORE_H
#define __ASM_ARM_SEMAPHORE_H

#include <linux/linkage.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/rwsem.h>

#include <asm/atomic.h>
#include <asm/locks.h>

struct semaphore {
 atomic_t count;
 int sleepers;
 wait_queue_head_t wait;
};

#define __SEMAPHORE_INIT(name, cnt)  {   .count = ATOMIC_INIT(cnt),   .wait = __WAIT_QUEUE_HEAD_INITIALIZER((name).wait),  }

#define __DECLARE_SEMAPHORE_GENERIC(name,count)   struct semaphore name = __SEMAPHORE_INIT(name,count)

#define DECLARE_MUTEX(name) __DECLARE_SEMAPHORE_GENERIC(name,1)
#define DECLARE_MUTEX_LOCKED(name) __DECLARE_SEMAPHORE_GENERIC(name,0)

#endif
