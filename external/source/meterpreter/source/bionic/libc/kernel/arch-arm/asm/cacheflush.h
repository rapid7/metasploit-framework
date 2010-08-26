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
#ifndef _ASMARM_CACHEFLUSH_H
#define _ASMARM_CACHEFLUSH_H

#include <linux/sched.h>
#include <linux/mm.h>

#include <asm/glue.h>
#include <asm/shmparam.h>

#define CACHE_COLOUR(vaddr) ((vaddr & (SHMLBA - 1)) >> PAGE_SHIFT)

#undef _CACHE
#undef MULTI_CACHE

#if !defined(_CACHE) && !defined(MULTI_CACHE)
#error Unknown cache maintainence model
#endif

#define PG_dcache_dirty PG_arch_1

struct cpu_cache_fns {
 void (*flush_kern_all)(void);
 void (*flush_user_all)(void);
 void (*flush_user_range)(unsigned long, unsigned long, unsigned int);

 void (*coherent_kern_range)(unsigned long, unsigned long);
 void (*coherent_user_range)(unsigned long, unsigned long);
 void (*flush_kern_dcache_page)(void *);

 void (*dma_inv_range)(unsigned long, unsigned long);
 void (*dma_clean_range)(unsigned long, unsigned long);
 void (*dma_flush_range)(unsigned long, unsigned long);
};

#ifdef MULTI_CACHE

#define __cpuc_flush_kern_all cpu_cache.flush_kern_all
#define __cpuc_flush_user_all cpu_cache.flush_user_all
#define __cpuc_flush_user_range cpu_cache.flush_user_range
#define __cpuc_coherent_kern_range cpu_cache.coherent_kern_range
#define __cpuc_coherent_user_range cpu_cache.coherent_user_range
#define __cpuc_flush_dcache_page cpu_cache.flush_kern_dcache_page

#define dmac_inv_range cpu_cache.dma_inv_range
#define dmac_clean_range cpu_cache.dma_clean_range
#define dmac_flush_range cpu_cache.dma_flush_range

#else

#define __cpuc_flush_kern_all __glue(_CACHE,_flush_kern_cache_all)
#define __cpuc_flush_user_all __glue(_CACHE,_flush_user_cache_all)
#define __cpuc_flush_user_range __glue(_CACHE,_flush_user_cache_range)
#define __cpuc_coherent_kern_range __glue(_CACHE,_coherent_kern_range)
#define __cpuc_coherent_user_range __glue(_CACHE,_coherent_user_range)
#define __cpuc_flush_dcache_page __glue(_CACHE,_flush_kern_dcache_page)

#define dmac_inv_range __glue(_CACHE,_dma_inv_range)
#define dmac_clean_range __glue(_CACHE,_dma_clean_range)
#define dmac_flush_range __glue(_CACHE,_dma_flush_range)

#endif

#define flush_cache_vmap(start, end) flush_cache_all()
#define flush_cache_vunmap(start, end) flush_cache_all()

#define copy_to_user_page(vma, page, vaddr, dst, src, len)   do {   memcpy(dst, src, len);   flush_ptrace_access(vma, page, vaddr, dst, len, 1);  } while (0)

#define copy_from_user_page(vma, page, vaddr, dst, src, len)   do {   memcpy(dst, src, len);   } while (0)

#define flush_cache_all() __cpuc_flush_kern_all()
#define flush_cache_user_range(vma,start,end)   __cpuc_coherent_user_range((start) & PAGE_MASK, PAGE_ALIGN(end))
#define flush_icache_range(s,e) __cpuc_coherent_kern_range(s,e)
#define clean_dcache_area(start,size) cpu_dcache_clean_area(start, size)

#define flush_dcache_mmap_lock(mapping)   write_lock_irq(&(mapping)->tree_lock)
#define flush_dcache_mmap_unlock(mapping)   write_unlock_irq(&(mapping)->tree_lock)

#define flush_icache_user_range(vma,page,addr,len)   flush_dcache_page(page)

#define flush_icache_page(vma,page) do { } while (0)

#define __cacheid_present(val) (val != read_cpuid(CPUID_ID))
#define __cacheid_vivt(val) ((val & (15 << 25)) != (14 << 25))
#define __cacheid_vipt(val) ((val & (15 << 25)) == (14 << 25))
#define __cacheid_vipt_nonaliasing(val) ((val & (15 << 25 | 1 << 23)) == (14 << 25))
#define __cacheid_vipt_aliasing(val) ((val & (15 << 25 | 1 << 23)) == (14 << 25 | 1 << 23))

#define cache_is_vivt()   ({   unsigned int __val = read_cpuid(CPUID_CACHETYPE);   (!__cacheid_present(__val)) || __cacheid_vivt(__val);   })

#define cache_is_vipt()   ({   unsigned int __val = read_cpuid(CPUID_CACHETYPE);   __cacheid_present(__val) && __cacheid_vipt(__val);   })

#define cache_is_vipt_nonaliasing()   ({   unsigned int __val = read_cpuid(CPUID_CACHETYPE);   __cacheid_present(__val) &&   __cacheid_vipt_nonaliasing(__val);   })

#define cache_is_vipt_aliasing()   ({   unsigned int __val = read_cpuid(CPUID_CACHETYPE);   __cacheid_present(__val) &&   __cacheid_vipt_aliasing(__val);   })

#endif
