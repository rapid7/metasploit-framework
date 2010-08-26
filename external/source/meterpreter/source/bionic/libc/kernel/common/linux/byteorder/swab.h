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
#ifndef _LINUX_BYTEORDER_SWAB_H
#define _LINUX_BYTEORDER_SWAB_H

#include <linux/compiler.h>

#define ___swab16(x)  ({   __u16 __x = (x);   ((__u16)(   (((__u16)(__x) & (__u16)0x00ffU) << 8) |   (((__u16)(__x) & (__u16)0xff00U) >> 8) ));  })

#define ___swab32(x)  ({   __u32 __x = (x);   ((__u32)(   (((__u32)(__x) & (__u32)0x000000ffUL) << 24) |   (((__u32)(__x) & (__u32)0x0000ff00UL) << 8) |   (((__u32)(__x) & (__u32)0x00ff0000UL) >> 8) |   (((__u32)(__x) & (__u32)0xff000000UL) >> 24) ));  })

#define ___swab64(x)  ({   __u64 __x = (x);   ((__u64)(   (__u64)(((__u64)(__x) & (__u64)0x00000000000000ffULL) << 56) |   (__u64)(((__u64)(__x) & (__u64)0x000000000000ff00ULL) << 40) |   (__u64)(((__u64)(__x) & (__u64)0x0000000000ff0000ULL) << 24) |   (__u64)(((__u64)(__x) & (__u64)0x00000000ff000000ULL) << 8) |   (__u64)(((__u64)(__x) & (__u64)0x000000ff00000000ULL) >> 8) |   (__u64)(((__u64)(__x) & (__u64)0x0000ff0000000000ULL) >> 24) |   (__u64)(((__u64)(__x) & (__u64)0x00ff000000000000ULL) >> 40) |   (__u64)(((__u64)(__x) & (__u64)0xff00000000000000ULL) >> 56) ));  })

#define ___constant_swab16(x)   ((__u16)(   (((__u16)(x) & (__u16)0x00ffU) << 8) |   (((__u16)(x) & (__u16)0xff00U) >> 8) ))
#define ___constant_swab32(x)   ((__u32)(   (((__u32)(x) & (__u32)0x000000ffUL) << 24) |   (((__u32)(x) & (__u32)0x0000ff00UL) << 8) |   (((__u32)(x) & (__u32)0x00ff0000UL) >> 8) |   (((__u32)(x) & (__u32)0xff000000UL) >> 24) ))
#define ___constant_swab64(x)   ((__u64)(   (__u64)(((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) |   (__u64)(((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40) |   (__u64)(((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) |   (__u64)(((__u64)(x) & (__u64)0x00000000ff000000ULL) << 8) |   (__u64)(((__u64)(x) & (__u64)0x000000ff00000000ULL) >> 8) |   (__u64)(((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) |   (__u64)(((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40) |   (__u64)(((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56) ))

#ifndef __arch__swab16
#define __arch__swab16(x) ({ __u16 __tmp = (x) ; ___swab16(__tmp); })
#endif
#ifndef __arch__swab32
#define __arch__swab32(x) ({ __u32 __tmp = (x) ; ___swab32(__tmp); })
#endif
#ifndef __arch__swab64
#define __arch__swab64(x) ({ __u64 __tmp = (x) ; ___swab64(__tmp); })
#endif

#ifndef __arch__swab16p
#define __arch__swab16p(x) __arch__swab16(*(x))
#endif
#ifndef __arch__swab32p
#define __arch__swab32p(x) __arch__swab32(*(x))
#endif
#ifndef __arch__swab64p
#define __arch__swab64p(x) __arch__swab64(*(x))
#endif

#ifndef __arch__swab16s
#define __arch__swab16s(x) do { *(x) = __arch__swab16p((x)); } while (0)
#endif
#ifndef __arch__swab32s
#define __arch__swab32s(x) do { *(x) = __arch__swab32p((x)); } while (0)
#endif
#ifndef __arch__swab64s
#define __arch__swab64s(x) do { *(x) = __arch__swab64p((x)); } while (0)
#endif

#if defined(__GNUC__) && defined(__OPTIMIZE__)
#define __swab16(x)  (__builtin_constant_p((__u16)(x)) ?   ___swab16((x)) :   __fswab16((x)))
#define __swab32(x)  (__builtin_constant_p((__u32)(x)) ?   ___swab32((x)) :   __fswab32((x)))
#define __swab64(x)  (__builtin_constant_p((__u64)(x)) ?   ___swab64((x)) :   __fswab64((x)))
#else
#define __swab16(x) __fswab16(x)
#define __swab32(x) __fswab32(x)
#define __swab64(x) __fswab64(x)
#endif

#ifdef __BYTEORDER_HAS_U64__
#ifdef __SWAB_64_THRU_32__
#else
#endif
#endif
#endif
