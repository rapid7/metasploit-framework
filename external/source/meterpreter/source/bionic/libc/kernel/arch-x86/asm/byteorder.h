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
#ifndef _ASM_X86_BYTEORDER_H
#define _ASM_X86_BYTEORDER_H

#include <asm/types.h>
#include <linux/compiler.h>

#ifdef __GNUC__

#ifdef __i386__

static __inline__ __attribute_const__ __u32 ___arch__swab32(__u32 x)
{
 __asm__("xchgb %b0,%h0\n\t"
 "rorl $16,%0\n\t"
 "xchgb %b0,%h0"
 :"=q" (x)
 : "0" (x));
 return x;
}

static __inline__ __attribute_const__ __u64 ___arch__swab64(__u64 val)
{
 union {
 struct { __u32 a,b; } s;
 __u64 u;
 } v;
 v.u = val;
 v.s.a = ___arch__swab32(v.s.a);
 v.s.b = ___arch__swab32(v.s.b);
 __asm__("xchgl %0,%1" : "=r" (v.s.a), "=r" (v.s.b) : "0" (v.s.a), "1" (v.s.b));
 return v.u;
}

#else

static __inline__ __attribute_const__ __u64 ___arch__swab64(__u64 x)
{
 __asm__("bswapq %0" : "=r" (x) : "0" (x));
 return x;
}

static __inline__ __attribute_const__ __u32 ___arch__swab32(__u32 x)
{
 __asm__("bswapl %0" : "=r" (x) : "0" (x));
 return x;
}

#endif

#define __arch__swab64(x) ___arch__swab64(x)
#define __arch__swab32(x) ___arch__swab32(x)

#define __BYTEORDER_HAS_U64__

#endif

#include <linux/byteorder/little_endian.h>

#endif
