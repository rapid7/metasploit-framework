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
#ifndef __LINUX_SMP_H
#define __LINUX_SMP_H

#define raw_smp_processor_id() 0
#define hard_smp_processor_id() 0
#define smp_call_function(func,info,retry,wait) (up_smp_call_function())
#define on_each_cpu(func,info,retry,wait)   ({   local_irq_disable();   func(info);   local_irq_enable();   0;   })
#define num_booting_cpus() 1
#define smp_prepare_boot_cpu() do {} while (0)
#define smp_processor_id() raw_smp_processor_id()
#define get_cpu() ({ preempt_disable(); smp_processor_id(); })
#define put_cpu() preempt_enable()
#define put_cpu_no_resched() preempt_enable_no_resched()

#endif
