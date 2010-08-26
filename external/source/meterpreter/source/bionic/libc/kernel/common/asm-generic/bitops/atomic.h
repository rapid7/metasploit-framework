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
#ifndef _ASM_GENERIC_BITOPS_ATOMIC_H_
#define _ASM_GENERIC_BITOPS_ATOMIC_H_

#include <asm/types.h>

#define BITOP_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))
#define BITOP_WORD(nr) ((nr) / BITS_PER_LONG)

#define _atomic_spin_lock_irqsave(l,f) do { local_irq_save(f); } while (0)
#define _atomic_spin_unlock_irqrestore(l,f) do { local_irq_restore(f); } while (0)

#endif
