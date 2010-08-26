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
#ifndef __ASM_CMPXCHG_H
#define __ASM_CMPXCHG_H

#include <linux/bitops.h>  

#define xchg(ptr,v) ((__typeof__(*(ptr)))__xchg((unsigned long)(v),(ptr),sizeof(*(ptr))))

struct __xchg_dummy { unsigned long a[100]; };
#define __xg(x) ((struct __xchg_dummy *)(x))

#define ll_low(x) *(((unsigned int*)&(x))+0)
#define ll_high(x) *(((unsigned int*)&(x))+1)
#define set_64bit(ptr,value)  (__builtin_constant_p(value) ?   __set_64bit_constant(ptr, value) :   __set_64bit_var(ptr, value) )
#define _set_64bit(ptr,value)  (__builtin_constant_p(value) ?   __set_64bit(ptr, (unsigned int)(value), (unsigned int)((value)>>32ULL) ) :   __set_64bit(ptr, ll_low(value), ll_high(value)) )

#define cmpxchg(ptr,o,n)  ({   __typeof__(*(ptr)) __ret;   if (likely(boot_cpu_data.x86 > 3))   __ret = __cmpxchg((ptr), (unsigned long)(o),   (unsigned long)(n), sizeof(*(ptr)));   else   __ret = cmpxchg_386((ptr), (unsigned long)(o),   (unsigned long)(n), sizeof(*(ptr)));   __ret;  })
#define cmpxchg_local(ptr,o,n)  ({   __typeof__(*(ptr)) __ret;   if (likely(boot_cpu_data.x86 > 3))   __ret = __cmpxchg_local((ptr), (unsigned long)(o),   (unsigned long)(n), sizeof(*(ptr)));   else   __ret = cmpxchg_386((ptr), (unsigned long)(o),   (unsigned long)(n), sizeof(*(ptr)));   __ret;  })
#define cmpxchg64(ptr,o,n)  ((__typeof__(*(ptr)))__cmpxchg64((ptr),(unsigned long long)(o),  (unsigned long long)(n)))
#define cmpxchg64_local(ptr,o,n)  ((__typeof__(*(ptr)))__cmpxchg64_local((ptr),(unsigned long long)(o),  (unsigned long long)(n)))
#endif
