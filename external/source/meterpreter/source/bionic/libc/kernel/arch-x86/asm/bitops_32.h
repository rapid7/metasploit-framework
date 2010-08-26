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
#ifndef _I386_BITOPS_H
#define _I386_BITOPS_H

#ifndef _LINUX_BITOPS_H
#error only <linux/bitops.h> can be included directly
#endif

#include <linux/compiler.h>
#include <asm/alternative.h>

#define ADDR (*(volatile long *) addr)

#define smp_mb__before_clear_bit() barrier()
#define smp_mb__after_clear_bit() barrier()
#define test_bit(nr,addr)  (__builtin_constant_p(nr) ?   constant_test_bit((nr),(addr)) :   variable_test_bit((nr),(addr)))
#undef ADDR

#include <asm-generic/bitops/fls64.h>
#endif
