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
#ifndef __ARCH_I386_ATOMIC__
#define __ARCH_I386_ATOMIC__

#include <linux/compiler.h>
#include <asm/processor.h>
#include <asm/cmpxchg.h>

typedef struct { int counter; } atomic_t;

#define ATOMIC_INIT(i) { (i) }

#define atomic_read(v) ((v)->counter)

#define atomic_set(v,i) (((v)->counter) = (i))

#define atomic_cmpxchg(v, old, new) (cmpxchg(&((v)->counter), (old), (new)))
#define atomic_xchg(v, new) (xchg(&((v)->counter), (new)))
#define atomic_inc_not_zero(v) atomic_add_unless((v), 1, 0)
#define atomic_inc_return(v) (atomic_add_return(1,v))
#define atomic_dec_return(v) (atomic_sub_return(1,v))
#define atomic_clear_mask(mask, addr)  __asm__ __volatile__(LOCK_PREFIX "andl %0,%1"  : : "r" (~(mask)),"m" (*addr) : "memory")
#define atomic_set_mask(mask, addr)  __asm__ __volatile__(LOCK_PREFIX "orl %0,%1"  : : "r" (mask),"m" (*(addr)) : "memory")
#define smp_mb__before_atomic_dec() barrier()
#define smp_mb__after_atomic_dec() barrier()
#define smp_mb__before_atomic_inc() barrier()
#define smp_mb__after_atomic_inc() barrier()
#include <asm-generic/atomic.h>
#endif
