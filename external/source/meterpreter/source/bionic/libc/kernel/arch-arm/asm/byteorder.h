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
#ifndef __ASM_ARM_BYTEORDER_H
#define __ASM_ARM_BYTEORDER_H

#include <linux/compiler.h>
#include <asm/types.h>

static inline __attribute_const__ __u32 ___arch__swab32(__u32 x)
{
 __u32 t;

#ifndef __thumb__
 if (!__builtin_constant_p(x)) {

 asm ("eor\t%0, %1, %1, ror #16" : "=r" (t) : "r" (x));
 } else
#endif
 t = x ^ ((x << 16) | (x >> 16));

 x = (x << 24) | (x >> 8);
 t &= ~0x00FF0000;
 x ^= (t >> 8);

 return x;
}

#define __arch__swab32(x) ___arch__swab32(x)

#ifndef __STRICT_ANSI__
#define __BYTEORDER_HAS_U64__
#define __SWAB_64_THRU_32__
#endif

#ifdef __ARMEB__
#include <linux/byteorder/big_endian.h>
#else
#include <linux/byteorder/little_endian.h>
#endif

#endif

