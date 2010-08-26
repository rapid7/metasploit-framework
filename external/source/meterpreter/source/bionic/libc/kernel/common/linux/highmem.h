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
#ifndef _LINUX_HIGHMEM_H
#define _LINUX_HIGHMEM_H

#include <linux/fs.h>
#include <linux/mm.h>

#include <asm/cacheflush.h>

#ifndef ARCH_HAS_FLUSH_ANON_PAGE
#endif
#ifndef ARCH_HAS_FLUSH_KERNEL_DCACHE_PAGE
#endif
#define kunmap(page) do { (void) (page); } while (0)
#define kmap_atomic(page, idx) page_address(page)
#define kunmap_atomic(addr, idx) do { } while (0)
#define kmap_atomic_pfn(pfn, idx) page_address(pfn_to_page(pfn))
#define kmap_atomic_to_page(ptr) virt_to_page(ptr)
#ifndef __HAVE_ARCH_ALLOC_ZEROED_USER_HIGHPAGE
#endif
#endif
