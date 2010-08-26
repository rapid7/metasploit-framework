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
#ifndef _ASM_FIXMAP_H
#define _ASM_FIXMAP_H

#include <linux/kernel.h>
#include <asm/page.h>

enum fixed_addresses {
#define FIX_N_COLOURS 16
 FIX_CMAP_BEGIN,
 FIX_CMAP_END = FIX_CMAP_BEGIN + FIX_N_COLOURS,
 FIX_UNCACHED,
 __end_of_fixed_addresses
};

#define set_fixmap(idx, phys)   __set_fixmap(idx, phys, PAGE_KERNEL)

#define set_fixmap_nocache(idx, phys)   __set_fixmap(idx, phys, PAGE_KERNEL_NOCACHE)

#define FIXADDR_TOP (P4SEG - PAGE_SIZE)
#define FIXADDR_SIZE (__end_of_fixed_addresses << PAGE_SHIFT)
#define FIXADDR_START (FIXADDR_TOP - FIXADDR_SIZE)

#define __fix_to_virt(x) (FIXADDR_TOP - ((x) << PAGE_SHIFT))
#define __virt_to_fix(x) ((FIXADDR_TOP - ((x)&PAGE_MASK)) >> PAGE_SHIFT)

#endif
