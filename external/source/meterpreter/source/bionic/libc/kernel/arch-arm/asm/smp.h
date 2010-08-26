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
#ifndef __ASM_ARM_SMP_H
#define __ASM_ARM_SMP_H

#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/thread_info.h>

#include <asm/arch/smp.h>

#error "<asm-arm/smp.h> included in non-SMP build"

#define raw_smp_processor_id() (current_thread_info()->cpu)

#define PROC_CHANGE_PENALTY 15

struct seq_file;

struct secondary_data {
 unsigned long pgdir;
 void *stack;
};

#endif
