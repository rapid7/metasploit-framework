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
#ifndef __LINUX_SEQLOCK_H
#define __LINUX_SEQLOCK_H

#include <linux/spinlock.h>
#include <linux/preempt.h>

typedef struct {
 unsigned sequence;
 spinlock_t lock;
} seqlock_t;

#define __SEQLOCK_UNLOCKED(lockname)   { 0, __SPIN_LOCK_UNLOCKED(lockname) }

#define SEQLOCK_UNLOCKED   __SEQLOCK_UNLOCKED(old_style_seqlock_init)

#define seqlock_init(x)   do { *(x) = (seqlock_t) __SEQLOCK_UNLOCKED(x); } while (0)

#define DEFINE_SEQLOCK(x)   seqlock_t x = __SEQLOCK_UNLOCKED(x)

#define SEQCNT_ZERO { 0 }
#define seqcount_init(x) do { *(x) = (seqcount_t) SEQCNT_ZERO; } while (0)

#define write_seqlock_irqsave(lock, flags)   do { local_irq_save(flags); write_seqlock(lock); } while (0)
#define write_seqlock_irq(lock)   do { local_irq_disable(); write_seqlock(lock); } while (0)
#define write_seqlock_bh(lock)   do { local_bh_disable(); write_seqlock(lock); } while (0)
#define write_sequnlock_irqrestore(lock, flags)   do { write_sequnlock(lock); local_irq_restore(flags); } while(0)
#define write_sequnlock_irq(lock)   do { write_sequnlock(lock); local_irq_enable(); } while(0)
#define write_sequnlock_bh(lock)   do { write_sequnlock(lock); local_bh_enable(); } while(0)
#define read_seqbegin_irqsave(lock, flags)   ({ local_irq_save(flags); read_seqbegin(lock); })
#define read_seqretry_irqrestore(lock, iv, flags)   ({   int ret = read_seqretry(lock, iv);   local_irq_restore(flags);   ret;   })
#endif
