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
#ifndef LINUX_HARDIRQ_H
#define LINUX_HARDIRQ_H

#include <linux/preempt.h>
#include <linux/smp_lock.h>
#include <linux/lockdep.h>
#include <asm/hardirq.h>
#include <asm/system.h>

#define PREEMPT_BITS 8
#define SOFTIRQ_BITS 8

#ifndef HARDIRQ_BITS
#define HARDIRQ_BITS 12

#if 1 << HARDIRQ_BITS < NR_IRQS
#error HARDIRQ_BITS is too low!
#endif
#endif

#define PREEMPT_SHIFT 0
#define SOFTIRQ_SHIFT (PREEMPT_SHIFT + PREEMPT_BITS)
#define HARDIRQ_SHIFT (SOFTIRQ_SHIFT + SOFTIRQ_BITS)

#define __IRQ_MASK(x) ((1UL << (x))-1)

#define PREEMPT_MASK (__IRQ_MASK(PREEMPT_BITS) << PREEMPT_SHIFT)
#define SOFTIRQ_MASK (__IRQ_MASK(SOFTIRQ_BITS) << SOFTIRQ_SHIFT)
#define HARDIRQ_MASK (__IRQ_MASK(HARDIRQ_BITS) << HARDIRQ_SHIFT)

#define PREEMPT_OFFSET (1UL << PREEMPT_SHIFT)
#define SOFTIRQ_OFFSET (1UL << SOFTIRQ_SHIFT)
#define HARDIRQ_OFFSET (1UL << HARDIRQ_SHIFT)

#if PREEMPT_ACTIVE < 1 << HARDIRQ_SHIFT + HARDIRQ_BITS
#error PREEMPT_ACTIVE is too low!
#endif

#define hardirq_count() (preempt_count() & HARDIRQ_MASK)
#define softirq_count() (preempt_count() & SOFTIRQ_MASK)
#define irq_count() (preempt_count() & (HARDIRQ_MASK | SOFTIRQ_MASK))

#define in_irq() (hardirq_count())
#define in_softirq() (softirq_count())
#define in_interrupt() (irq_count())

#define in_atomic() ((preempt_count() & ~PREEMPT_ACTIVE) != 0)

#define preemptible() 0
#define IRQ_EXIT_OFFSET HARDIRQ_OFFSET

#define synchronize_irq(irq) barrier()

struct task_struct;

#define irq_enter()   do {   account_system_vtime(current);   add_preempt_count(HARDIRQ_OFFSET);   trace_hardirq_enter();   } while (0)
#define __irq_exit()   do {   trace_hardirq_exit();   account_system_vtime(current);   sub_preempt_count(HARDIRQ_OFFSET);   } while (0)

#define nmi_enter() do { lockdep_off(); irq_enter(); } while (0)
#define nmi_exit() do { __irq_exit(); lockdep_on(); } while (0)

#endif
