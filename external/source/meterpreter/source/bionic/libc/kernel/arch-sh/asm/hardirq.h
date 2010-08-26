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
#ifndef __ASM_SH_HARDIRQ_H
#define __ASM_SH_HARDIRQ_H

#include <linux/threads.h>
#include <linux/irq.h>

typedef struct {
 unsigned int __softirq_pending;
} ____cacheline_aligned irq_cpustat_t;

#include <linux/irq_cpustat.h>  

#endif
