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

#define FIXADDR_USER_START __fix_to_virt(FIX_VDSO)
#define FIXADDR_USER_END __fix_to_virt(FIX_VDSO - 1)

#ifndef __ASSEMBLY__
#include <linux/kernel.h>
#include <asm/acpi.h>
#include <asm/apicdef.h>
#include <asm/page.h>

enum fixed_addresses {
 FIX_HOLE,
 FIX_VDSO,
 FIX_DBGP_BASE,
 FIX_EARLYCON_MEM_BASE,
 __end_of_permanent_fixed_addresses,

#define NR_FIX_BTMAPS 16
 FIX_BTMAP_END = __end_of_permanent_fixed_addresses,
 FIX_BTMAP_BEGIN = FIX_BTMAP_END + NR_FIX_BTMAPS - 1,
 FIX_WP_TEST,
 __end_of_fixed_addresses
};

#define set_fixmap(idx, phys)   __set_fixmap(idx, phys, PAGE_KERNEL)

#define set_fixmap_nocache(idx, phys)   __set_fixmap(idx, phys, PAGE_KERNEL_NOCACHE)

#define clear_fixmap(idx)   __set_fixmap(idx, 0, __pgprot(0))

#define FIXADDR_TOP ((unsigned long)__FIXADDR_TOP)

#define __FIXADDR_SIZE (__end_of_permanent_fixed_addresses << PAGE_SHIFT)
#define __FIXADDR_BOOT_SIZE (__end_of_fixed_addresses << PAGE_SHIFT)
#define FIXADDR_START (FIXADDR_TOP - __FIXADDR_SIZE)
#define FIXADDR_BOOT_START (FIXADDR_TOP - __FIXADDR_BOOT_SIZE)

#define __fix_to_virt(x) (FIXADDR_TOP - ((x) << PAGE_SHIFT))
#define __virt_to_fix(x) ((FIXADDR_TOP - ((x)&PAGE_MASK)) >> PAGE_SHIFT)

#endif
#endif
