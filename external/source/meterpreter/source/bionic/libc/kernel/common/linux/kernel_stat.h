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
#ifndef _LINUX_KERNEL_STAT_H
#define _LINUX_KERNEL_STAT_H

#include <asm/irq.h>
#include <linux/smp.h>
#include <linux/threads.h>
#include <linux/percpu.h>
#include <linux/cpumask.h>
#include <asm/cputime.h>

struct cpu_usage_stat {
 cputime64_t user;
 cputime64_t nice;
 cputime64_t system;
 cputime64_t softirq;
 cputime64_t irq;
 cputime64_t idle;
 cputime64_t iowait;
 cputime64_t steal;
};

struct kernel_stat {
 struct cpu_usage_stat cpustat;
 unsigned int irqs[NR_IRQS];
};

#define kstat_cpu(cpu) per_cpu(kstat, cpu)

#define kstat_this_cpu __get_cpu_var(kstat)

#endif
