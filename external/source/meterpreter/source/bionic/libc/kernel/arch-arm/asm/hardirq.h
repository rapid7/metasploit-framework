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

#include <linux/cache.h>
#include <linux/threads.h>
#include <asm/irq.h>

typedef struct {
 unsigned int __softirq_pending;
 unsigned int local_timer_irqs;
} ____cacheline_aligned irq_cpustat_t;

#include <linux/irq_cpustat.h>  

#if NR_IRQS > 256
#define HARDIRQ_BITS 9
#else
#define HARDIRQ_BITS 8
#endif

#if 1 << HARDIRQ_BITS < NR_IRQS
#error HARDIRQ_BITS is too low!
#endif

#define __ARCH_IRQ_EXIT_IRQS_DISABLED 1

#endif
