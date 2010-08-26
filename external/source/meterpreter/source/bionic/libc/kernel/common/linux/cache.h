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
#ifndef __LINUX_CACHE_H
#define __LINUX_CACHE_H

#include <linux/kernel.h>
#include <asm/cache.h>

#ifndef L1_CACHE_ALIGN
#define L1_CACHE_ALIGN(x) ALIGN(x, L1_CACHE_BYTES)
#endif

#ifndef SMP_CACHE_BYTES
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#endif

#ifndef __read_mostly
#define __read_mostly
#endif

#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

#ifndef ____cacheline_aligned_in_smp
#define ____cacheline_aligned_in_smp
#endif

#ifndef __cacheline_aligned
#define __cacheline_aligned   __attribute__((__aligned__(SMP_CACHE_BYTES),   __section__(".data.cacheline_aligned")))
#endif

#ifndef __cacheline_aligned_in_smp
#define __cacheline_aligned_in_smp
#endif

#ifndef INTERNODE_CACHE_SHIFT
#define INTERNODE_CACHE_SHIFT L1_CACHE_SHIFT
#endif

#ifndef ____cacheline_internodealigned_in_smp
#define ____cacheline_internodealigned_in_smp
#endif

#endif
