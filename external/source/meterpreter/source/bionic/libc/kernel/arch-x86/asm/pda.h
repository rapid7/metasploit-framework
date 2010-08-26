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
#ifndef X86_64_PDA_H
#define X86_64_PDA_H

#ifndef __ASSEMBLY__
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/cache.h>
#include <asm/page.h>

struct x8664_pda {
 struct task_struct *pcurrent;
 unsigned long data_offset;
 unsigned long kernelstack;
 unsigned long oldrsp;
 int irqcount;
 int cpunumber;
 char *irqstackptr;
 int nodenumber;
 unsigned int __softirq_pending;
 unsigned int __nmi_count;
 short mmu_state;
 short isidle;
 struct mm_struct *active_mm;
 unsigned apic_timer_irqs;
 unsigned irq0_irqs;
 unsigned irq_resched_count;
 unsigned irq_call_count;
 unsigned irq_tlb_count;
 unsigned irq_thermal_count;
 unsigned irq_threshold_count;
 unsigned irq_spurious_count;
} ____cacheline_aligned_in_smp;

#define cpu_pda(i) (_cpu_pda[i])

#define pda_offset(field) offsetof(struct x8664_pda, field)

#define pda_to_op(op,field,val) do {   typedef typeof(_proxy_pda.field) T__;   if (0) { T__ tmp__; tmp__ = (val); }     switch (sizeof(_proxy_pda.field)) {   case 2:   asm(op "w %1,%%gs:%c2" :   "+m" (_proxy_pda.field) :   "ri" ((T__)val),   "i"(pda_offset(field)));   break;   case 4:   asm(op "l %1,%%gs:%c2" :   "+m" (_proxy_pda.field) :   "ri" ((T__)val),   "i" (pda_offset(field)));   break;   case 8:   asm(op "q %1,%%gs:%c2":   "+m" (_proxy_pda.field) :   "ri" ((T__)val),   "i"(pda_offset(field)));   break;   default:   __bad_pda_field();   }   } while (0)

#define pda_from_op(op,field) ({   typeof(_proxy_pda.field) ret__;   switch (sizeof(_proxy_pda.field)) {   case 2:   asm(op "w %%gs:%c1,%0" :   "=r" (ret__) :   "i" (pda_offset(field)),   "m" (_proxy_pda.field));   break;   case 4:   asm(op "l %%gs:%c1,%0":   "=r" (ret__):   "i" (pda_offset(field)),   "m" (_proxy_pda.field));   break;   case 8:   asm(op "q %%gs:%c1,%0":   "=r" (ret__) :   "i" (pda_offset(field)),   "m" (_proxy_pda.field));   break;   default:   __bad_pda_field();   }   ret__; })

#define read_pda(field) pda_from_op("mov",field)
#define write_pda(field,val) pda_to_op("mov",field,val)
#define add_pda(field,val) pda_to_op("add",field,val)
#define sub_pda(field,val) pda_to_op("sub",field,val)
#define or_pda(field,val) pda_to_op("or",field,val)

#define test_and_clear_bit_pda(bit,field) ({   int old__;   asm volatile("btr %2,%%gs:%c3\n\tsbbl %0,%0"   : "=r" (old__), "+m" (_proxy_pda.field)   : "dIr" (bit), "i" (pda_offset(field)) : "memory");   old__;  })

#endif

#define PDA_STACKOFFSET (5*8)

#endif
