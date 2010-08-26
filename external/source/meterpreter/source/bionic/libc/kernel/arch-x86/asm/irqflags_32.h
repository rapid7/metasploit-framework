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
#ifndef _ASM_IRQFLAGS_H
#define _ASM_IRQFLAGS_H
#include <asm/processor-flags.h>

#ifndef __ASSEMBLY__
#endif
#ifndef __ASSEMBLY__
#else
#define DISABLE_INTERRUPTS(clobbers) cli
#define ENABLE_INTERRUPTS(clobbers) sti
#define ENABLE_INTERRUPTS_SYSEXIT sti; sysexit
#define INTERRUPT_RETURN iret
#define GET_CR0_INTO_EAX movl %cr0, %eax
#endif
#ifndef __ASSEMBLY__
#define raw_local_save_flags(flags)   do { (flags) = __raw_local_save_flags(); } while (0)
#define raw_local_irq_save(flags)   do { (flags) = __raw_local_irq_save(); } while (0)
#endif
#define TRACE_IRQS_ON
#define TRACE_IRQS_OFF
#define LOCKDEP_SYS_EXIT
#endif
