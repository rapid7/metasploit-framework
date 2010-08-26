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
#ifndef __ASM_HARDIRQ_H
#define __ASM_HARDIRQ_H

#include <linux/threads.h>
#include <linux/irq.h>

typedef struct {
 unsigned int __softirq_pending;
 unsigned long idle_timestamp;
 unsigned int __nmi_count;
 unsigned int apic_timer_irqs;
 unsigned int irq0_irqs;
 unsigned int irq_resched_count;
 unsigned int irq_call_count;
 unsigned int irq_tlb_count;
 unsigned int irq_thermal_count;
 unsigned int irq_spurious_count;
} ____cacheline_aligned irq_cpustat_t;

#define __ARCH_IRQ_STAT
#define __IRQ_STAT(cpu, member) (per_cpu(irq_stat, cpu).member)

#include <linux/irq_cpustat.h>

#endif
