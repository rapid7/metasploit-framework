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
#ifndef __LINUX_GFP_H
#define __LINUX_GFP_H

#include <linux/mmzone.h>
#include <linux/stddef.h>
#include <linux/linkage.h>

struct vm_area_struct;

#define __GFP_DMA ((__force gfp_t)0x01u)
#define __GFP_HIGHMEM ((__force gfp_t)0x02u)
#if BITS_PER_LONG < 64
#define __GFP_DMA32 ((__force gfp_t)0x00)  
#else
#define __GFP_DMA32 ((__force gfp_t)0x04)  
#endif

#define __GFP_WAIT ((__force gfp_t)0x10u)  
#define __GFP_HIGH ((__force gfp_t)0x20u)  
#define __GFP_IO ((__force gfp_t)0x40u)  
#define __GFP_FS ((__force gfp_t)0x80u)  
#define __GFP_COLD ((__force gfp_t)0x100u)  
#define __GFP_NOWARN ((__force gfp_t)0x200u)  
#define __GFP_REPEAT ((__force gfp_t)0x400u)  
#define __GFP_NOFAIL ((__force gfp_t)0x800u)  
#define __GFP_NORETRY ((__force gfp_t)0x1000u) 
#define __GFP_NO_GROW ((__force gfp_t)0x2000u) 
#define __GFP_COMP ((__force gfp_t)0x4000u) 
#define __GFP_ZERO ((__force gfp_t)0x8000u) 
#define __GFP_NOMEMALLOC ((__force gfp_t)0x10000u)  
#define __GFP_HARDWALL ((__force gfp_t)0x20000u)  

#define __GFP_BITS_SHIFT 20  
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))

#define GFP_LEVEL_MASK (__GFP_WAIT|__GFP_HIGH|__GFP_IO|__GFP_FS|   __GFP_COLD|__GFP_NOWARN|__GFP_REPEAT|   __GFP_NOFAIL|__GFP_NORETRY|__GFP_NO_GROW|__GFP_COMP|   __GFP_NOMEMALLOC|__GFP_HARDWALL)

#define GFP_NOWAIT (GFP_ATOMIC & ~__GFP_HIGH)

#define GFP_ATOMIC (__GFP_HIGH)
#define GFP_NOIO (__GFP_WAIT)
#define GFP_NOFS (__GFP_WAIT | __GFP_IO)
#define GFP_KERNEL (__GFP_WAIT | __GFP_IO | __GFP_FS)
#define GFP_USER (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
#define GFP_HIGHUSER (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL |   __GFP_HIGHMEM)

#define GFP_DMA __GFP_DMA

#define GFP_DMA32 __GFP_DMA32

#ifndef HAVE_ARCH_FREE_PAGE
#endif

#define alloc_pages(gfp_mask, order)   alloc_pages_node(numa_node_id(), gfp_mask, order)
#define alloc_page_vma(gfp_mask, vma, addr) alloc_pages(gfp_mask, 0)
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

#define __get_free_page(gfp_mask)   __get_free_pages((gfp_mask),0)

#define __get_dma_pages(gfp_mask, order)   __get_free_pages((gfp_mask) | GFP_DMA,(order))

#define __free_page(page) __free_pages((page), 0)
#define free_page(addr) free_pages((addr),0)

#endif
