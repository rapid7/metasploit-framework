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
#ifndef _LINUX_VMALLOC_H
#define _LINUX_VMALLOC_H

#include <linux/spinlock.h>
#include <asm/page.h>  

struct vm_area_struct;

#define VM_IOREMAP 0x00000001  
#define VM_ALLOC 0x00000002  
#define VM_MAP 0x00000004  
#define VM_USERMAP 0x00000008  
#define VM_VPAGES 0x00000010  

#ifndef IOREMAP_MAX_ORDER
#define IOREMAP_MAX_ORDER (7 + PAGE_SHIFT)  
#endif

struct vm_struct {
 void *addr;
 unsigned long size;
 unsigned long flags;
 struct page **pages;
 unsigned int nr_pages;
 unsigned long phys_addr;
 struct vm_struct *next;
};

#endif
