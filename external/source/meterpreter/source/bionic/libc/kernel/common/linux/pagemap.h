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
#ifndef _LINUX_PAGEMAP_H
#define _LINUX_PAGEMAP_H

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/highmem.h>
#include <linux/compiler.h>
#include <asm/uaccess.h>
#include <linux/gfp.h>

#define AS_EIO (__GFP_BITS_SHIFT + 0)  
#define AS_ENOSPC (__GFP_BITS_SHIFT + 1)  

#define PAGE_CACHE_SHIFT PAGE_SHIFT
#define PAGE_CACHE_SIZE PAGE_SIZE
#define PAGE_CACHE_MASK PAGE_MASK
#define PAGE_CACHE_ALIGN(addr) (((addr)+PAGE_CACHE_SIZE-1)&PAGE_CACHE_MASK)
#define page_cache_get(page) get_page(page)
#define page_cache_release(page) put_page(page)

#endif
