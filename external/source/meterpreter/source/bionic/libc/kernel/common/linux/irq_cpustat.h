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
#ifndef __irq_cpustat_h
#define __irq_cpustat_h

#ifndef __ARCH_IRQ_STAT

#define __IRQ_STAT(cpu, member) (irq_stat[cpu].member)
#endif

#define local_softirq_pending()   __IRQ_STAT(smp_processor_id(), __softirq_pending)

#define nmi_count(cpu) __IRQ_STAT((cpu), __nmi_count)  

#endif
