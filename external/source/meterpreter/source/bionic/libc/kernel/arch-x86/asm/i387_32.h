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
#ifndef __ASM_I386_I387_H
#define __ASM_I386_I387_H

#include <linux/sched.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <asm/processor.h>
#include <asm/sigcontext.h>
#include <asm/user.h>

#define restore_fpu(tsk)   alternative_input(   "nop ; frstor %1",   "fxrstor %1",   X86_FEATURE_FXSR,   "m" ((tsk)->thread.i387.fxsave))

#define kernel_fpu_end() do { stts(); preempt_enable(); } while(0)

#define safe_address (kstat_cpu(0).cpustat.user)

#define __unlazy_fpu( tsk ) do {   if (task_thread_info(tsk)->status & TS_USEDFPU) {   __save_init_fpu(tsk);   stts();   } else   tsk->fpu_counter = 0;  } while (0)
#define __clear_fpu( tsk )  do {   if (task_thread_info(tsk)->status & TS_USEDFPU) {   asm volatile("fnclex ; fwait");   task_thread_info(tsk)->status &= ~TS_USEDFPU;   stts();   }  } while (0)
#define unlazy_fpu( tsk ) do {   preempt_disable();   __unlazy_fpu(tsk);   preempt_enable();  } while (0)
#define clear_fpu( tsk ) do {   preempt_disable();   __clear_fpu( tsk );   preempt_enable();  } while (0)

#endif
