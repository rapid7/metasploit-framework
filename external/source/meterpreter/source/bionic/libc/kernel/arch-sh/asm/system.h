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
#ifndef __ASM_SH_SYSTEM_H
#define __ASM_SH_SYSTEM_H

#include <linux/irqflags.h>
#include <linux/compiler.h>
#include <linux/linkage.h>
#include <asm/types.h>
#include <asm/ptrace.h>

#define AT_VECTOR_SIZE_ARCH 5  

#define __icbi()  {   unsigned long __addr;   __addr = 0xa8000000;   __asm__ __volatile__(   "icbi   %0\n\t"   :     : "m" (__m(__addr)));  }

#define mb() __asm__ __volatile__ ("synco": : :"memory")
#define rmb() mb()
#define wmb() __asm__ __volatile__ ("synco": : :"memory")
#define ctrl_barrier() __icbi()
#define read_barrier_depends() do { } while(0)

#define smp_mb() barrier()
#define smp_rmb() barrier()
#define smp_wmb() barrier()
#define smp_read_barrier_depends() do { } while(0)

#define set_mb(var, value) do { (void)xchg(&var, value); } while (0)

#include <asm/cmpxchg-irq.h>

#define __xchg(ptr, x, size)  ({   unsigned long __xchg__res;   volatile void *__xchg_ptr = (ptr);   switch (size) {   case 4:   __xchg__res = xchg_u32(__xchg_ptr, x);   break;   case 1:   __xchg__res = xchg_u8(__xchg_ptr, x);   break;   default:   __xchg_called_with_bad_pointer();   __xchg__res = x;   break;   }     __xchg__res;  })

#define xchg(ptr,x)   ((__typeof__(*(ptr)))__xchg((ptr),(unsigned long)(x), sizeof(*(ptr))))

#define __HAVE_ARCH_CMPXCHG 1

#define cmpxchg(ptr,o,n)   ({   __typeof__(*(ptr)) _o_ = (o);   __typeof__(*(ptr)) _n_ = (n);   (__typeof__(*(ptr))) __cmpxchg((ptr), (unsigned long)_o_,   (unsigned long)_n_, sizeof(*(ptr)));   })

#define instruction_size(insn) (2)

#define BUILD_TRAP_HANDLER(name)  asmlinkage void name##_trap_handler(unsigned long r4, unsigned long r5,   unsigned long r6, unsigned long r7,   struct pt_regs __regs)

#define TRAP_HANDLER_DECL   struct pt_regs *regs = RELOC_HIDE(&__regs, 0);   unsigned int vec = regs->tra;   (void)vec;

#define arch_align_stack(x) (x)

struct mem_access {
 unsigned long (*from)(void *dst, const void *src, unsigned long cnt);
 unsigned long (*to)(void *dst, const void *src, unsigned long cnt);
};

#include "system_32.h"

#endif
