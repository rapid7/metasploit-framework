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
#ifndef _ASM_X86_CACHEFLUSH_H
#define _ASM_X86_CACHEFLUSH_H

#include <linux/mm.h>

#define flush_cache_all() do { } while (0)
#define flush_cache_mm(mm) do { } while (0)
#define flush_cache_dup_mm(mm) do { } while (0)
#define flush_cache_range(vma, start, end) do { } while (0)
#define flush_cache_page(vma, vmaddr, pfn) do { } while (0)
#define flush_dcache_page(page) do { } while (0)
#define flush_dcache_mmap_lock(mapping) do { } while (0)
#define flush_dcache_mmap_unlock(mapping) do { } while (0)
#define flush_icache_range(start, end) do { } while (0)
#define flush_icache_page(vma,pg) do { } while (0)
#define flush_icache_user_range(vma,pg,adr,len) do { } while (0)
#define flush_cache_vmap(start, end) do { } while (0)
#define flush_cache_vunmap(start, end) do { } while (0)

#define copy_to_user_page(vma, page, vaddr, dst, src, len)   memcpy(dst, src, len)
#define copy_from_user_page(vma, page, vaddr, dst, src, len)   memcpy(dst, src, len)

#endif
