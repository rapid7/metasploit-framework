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
#ifndef _LINUX_INTERRUPT_H
#define _LINUX_INTERRUPT_H

#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/bitops.h>
#include <linux/preempt.h>
#include <linux/cpumask.h>
#include <linux/irqreturn.h>
#include <linux/hardirq.h>
#include <linux/sched.h>
#include <linux/irqflags.h>
#include <asm/atomic.h>
#include <asm/ptrace.h>
#include <asm/system.h>

#define IRQF_TRIGGER_NONE 0x00000000
#define IRQF_TRIGGER_RISING 0x00000001
#define IRQF_TRIGGER_FALLING 0x00000002
#define IRQF_TRIGGER_HIGH 0x00000004
#define IRQF_TRIGGER_LOW 0x00000008
#define IRQF_TRIGGER_MASK (IRQF_TRIGGER_HIGH | IRQF_TRIGGER_LOW |   IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING)
#define IRQF_TRIGGER_PROBE 0x00000010

#define IRQF_DISABLED 0x00000020
#define IRQF_SAMPLE_RANDOM 0x00000040
#define IRQF_SHARED 0x00000080
#define IRQF_PROBE_SHARED 0x00000100
#define IRQF_TIMER 0x00000200
#define IRQF_PERCPU 0x00000400

#define SA_INTERRUPT IRQF_DISABLED
#define SA_SAMPLE_RANDOM IRQF_SAMPLE_RANDOM
#define SA_SHIRQ IRQF_SHARED
#define SA_PROBEIRQ IRQF_PROBE_SHARED
#define SA_PERCPU IRQF_PERCPU

#define SA_TRIGGER_LOW IRQF_TRIGGER_LOW
#define SA_TRIGGER_HIGH IRQF_TRIGGER_HIGH
#define SA_TRIGGER_FALLING IRQF_TRIGGER_FALLING
#define SA_TRIGGER_RISING IRQF_TRIGGER_RISING
#define SA_TRIGGER_MASK IRQF_TRIGGER_MASK

struct irqaction {
 irqreturn_t (*handler)(int, void *, struct pt_regs *);
 unsigned long flags;
 cpumask_t mask;
 const char *name;
 void *dev_id;
 struct irqaction *next;
 int irq;
 struct proc_dir_entry *dir;
};

#define local_irq_enable_in_hardirq() local_irq_enable()

#define disable_irq_nosync_lockdep(irq) disable_irq_nosync(irq)
#define disable_irq_lockdep(irq) disable_irq(irq)
#define enable_irq_lockdep(irq) enable_irq(irq)

#ifndef __ARCH_SET_SOFTIRQ_PENDING
#define set_softirq_pending(x) (local_softirq_pending() = (x))
#define or_softirq_pending(x) (local_softirq_pending() |= (x))
#endif

#define save_flags(x) save_flags(&x)
#define save_and_cli(x) save_and_cli(&x)

enum
{
 HI_SOFTIRQ=0,
 TIMER_SOFTIRQ,
 NET_TX_SOFTIRQ,
 NET_RX_SOFTIRQ,
 BLOCK_SOFTIRQ,
 TASKLET_SOFTIRQ
};

struct softirq_action
{
 void (*action)(struct softirq_action *);
 void *data;
};

#define __raise_softirq_irqoff(nr) do { or_softirq_pending(1UL << (nr)); } while (0)

struct tasklet_struct
{
 struct tasklet_struct *next;
 unsigned long state;
 atomic_t count;
 void (*func)(unsigned long);
 unsigned long data;
};

#define DECLARE_TASKLET(name, func, data)  struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }

#define DECLARE_TASKLET_DISABLED(name, func, data)  struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }

enum
{
 TASKLET_STATE_SCHED,
 TASKLET_STATE_RUN
};

#define tasklet_trylock(t) 1
#define tasklet_unlock_wait(t) do { } while (0)
#define tasklet_unlock(t) do { } while (0)

#endif
