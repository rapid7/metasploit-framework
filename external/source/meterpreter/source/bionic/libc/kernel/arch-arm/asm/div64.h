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
#ifndef __ASM_ARM_DIV64
#define __ASM_ARM_DIV64

#include <asm/system.h>

#ifdef __ARMEB__
#define __xh "r0"
#define __xl "r1"
#else
#define __xl "r0"
#define __xh "r1"
#endif

#define do_div(n,base)  ({   register unsigned int __base asm("r4") = base;   register unsigned long long __n asm("r0") = n;   register unsigned long long __res asm("r2");   register unsigned int __rem asm(__xh);   asm( __asmeq("%0", __xh)   __asmeq("%1", "r2")   __asmeq("%2", "r0")   __asmeq("%3", "r4")   "bl	__do_div64"   : "=r" (__rem), "=r" (__res)   : "r" (__n), "r" (__base)   : "ip", "lr", "cc");   n = __res;   __rem;  })

#endif
