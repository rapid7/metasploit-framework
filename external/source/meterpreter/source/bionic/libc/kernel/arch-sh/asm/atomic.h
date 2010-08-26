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
#ifndef __ASM_SH_ATOMIC_H
#define __ASM_SH_ATOMIC_H

typedef struct { volatile int counter; } atomic_t;

#define ATOMIC_INIT(i) ( (atomic_t) { (i) } )

#define atomic_read(v) ((v)->counter)
#define atomic_set(v,i) ((v)->counter = (i))

#include <linux/compiler.h>
#include <asm/system.h>

#include <asm/atomic-llsc.h>

#define atomic_add_negative(a, v) (atomic_add_return((a), (v)) < 0)

#define atomic_dec_return(v) atomic_sub_return(1,(v))
#define atomic_inc_return(v) atomic_add_return(1,(v))

#define atomic_inc_and_test(v) (atomic_inc_return(v) == 0)

#define atomic_sub_and_test(i,v) (atomic_sub_return((i), (v)) == 0)
#define atomic_dec_and_test(v) (atomic_sub_return(1, (v)) == 0)

#define atomic_inc(v) atomic_add(1,(v))
#define atomic_dec(v) atomic_sub(1,(v))

#define atomic_xchg(v, new) (xchg(&((v)->counter), new))
#define atomic_inc_not_zero(v) atomic_add_unless((v), 1, 0)
#define smp_mb__before_atomic_dec() barrier()
#define smp_mb__after_atomic_dec() barrier()
#define smp_mb__before_atomic_inc() barrier()
#define smp_mb__after_atomic_inc() barrier()
#include <asm-generic/atomic.h>
#endif
