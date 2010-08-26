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
#ifndef __ASM_SH_PAGE_H
#define __ASM_SH_PAGE_H

#include <linux/const.h>

#define PAGE_SHIFT 12

#define PAGE_SIZE (_AC(1, UL) << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))
#define PTE_MASK PAGE_MASK

#ifndef __ASSEMBLY__

struct page;
struct vm_area_struct;

#define __HAVE_ARCH_COPY_USER_HIGHPAGE

typedef struct { unsigned long pte_low; } pte_t;
typedef struct { unsigned long pgprot; } pgprot_t;
typedef struct { unsigned long pgd; } pgd_t;
#define pte_val(x) ((x).pte_low)
#define __pte(x) ((pte_t) { (x) } )

#define pgd_val(x) ((x).pgd)
#define pgprot_val(x) ((x).pgprot)

#define __pgd(x) ((pgd_t) { (x) } )
#define __pgprot(x) ((pgprot_t) { (x) } )

typedef struct page *pgtable_t;

#endif

#define __MEMORY_START CONFIG_MEMORY_START
#define __MEMORY_SIZE CONFIG_MEMORY_SIZE

#define PAGE_OFFSET CONFIG_PAGE_OFFSET

#define __pa(x) ((unsigned long)(x)-PAGE_OFFSET)
#define __va(x) ((void *)((unsigned long)(x)+PAGE_OFFSET))

#define pfn_to_kaddr(pfn) __va((pfn) << PAGE_SHIFT)
#define page_to_phys(page) (page_to_pfn(page) << PAGE_SHIFT)

#define PFN_START (__MEMORY_START >> PAGE_SHIFT)
#define ARCH_PFN_OFFSET (PFN_START)
#define virt_to_page(kaddr) pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
#define pfn_valid(pfn) ((pfn) >= min_low_pfn && (pfn) < max_low_pfn)
#define virt_addr_valid(kaddr) pfn_valid(__pa(kaddr) >> PAGE_SHIFT)

#define VM_DATA_DEFAULT_FLAGS (VM_READ | VM_WRITE | VM_EXEC |   VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

#include <asm-generic/memory_model.h>

#define __HAVE_ARCH_GATE_AREA

#define ARCH_KMALLOC_MINALIGN L1_CACHE_BYTES

#endif
