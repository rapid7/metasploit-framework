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
#ifndef __ASM_SH_PGTABLE_H
#define __ASM_SH_PGTABLE_H

#include <asm-generic/pgtable-nopmd.h>
#include <asm/page.h>

#ifndef __ASSEMBLY__
#include <asm/addrspace.h>
#include <asm/fixmap.h>

#define ZERO_PAGE(vaddr) (virt_to_page(empty_zero_page))

#endif

#define NEFF 32
#define NEFF_SIGN (1LL << (NEFF - 1))
#define NEFF_MASK (-1LL << NEFF)

#define NPHYS 29

#define NPHYS_SIGN (1LL << (NPHYS - 1))
#define NPHYS_MASK (-1LL << NPHYS)

#define PTE_MAGNITUDE 2  
#define PTE_SHIFT PAGE_SHIFT
#define PTE_BITS (PTE_SHIFT - PTE_MAGNITUDE)

#define PGDIR_SHIFT (PTE_SHIFT + PTE_BITS)
#define PGDIR_SIZE (1UL << PGDIR_SHIFT)
#define PGDIR_MASK (~(PGDIR_SIZE-1))

#define PTRS_PER_PTE (PAGE_SIZE / (1 << PTE_MAGNITUDE))
#define PTRS_PER_PGD (PAGE_SIZE / sizeof(pgd_t))

#define USER_PTRS_PER_PGD (TASK_SIZE/PGDIR_SIZE)
#define FIRST_USER_ADDRESS 0

#define PHYS_ADDR_MASK 0x1fffffff

#define PTE_PHYS_MASK (PHYS_ADDR_MASK & PAGE_MASK)

#define VMALLOC_START (P3SEG)
#define VMALLOC_END (FIXADDR_START-2*PAGE_SIZE)

#include <asm/pgtable_32.h>

#define __P000 PAGE_NONE
#define __P001 PAGE_READONLY
#define __P010 PAGE_COPY
#define __P011 PAGE_COPY
#define __P100 PAGE_EXECREAD
#define __P101 PAGE_EXECREAD
#define __P110 PAGE_COPY
#define __P111 PAGE_COPY

#define __S000 PAGE_NONE
#define __S001 PAGE_READONLY
#define __S010 PAGE_WRITEONLY
#define __S011 PAGE_SHARED
#define __S100 PAGE_EXECREAD
#define __S101 PAGE_EXECREAD
#define __S110 PAGE_RWX
#define __S111 PAGE_RWX

typedef pte_t *pte_addr_t;

#define kern_addr_valid(addr) (1)

#define io_remap_pfn_range(vma, vaddr, pfn, size, prot)   remap_pfn_range(vma, vaddr, pfn, size, prot)

#define pte_pfn(x) ((unsigned long)(((x).pte_low >> PAGE_SHIFT)))

#define pgtable_cache_init() do { } while (0)

struct mm_struct;
#define __HAVE_ARCH_PTEP_GET_AND_CLEAR

struct vm_area_struct;

#include <asm-generic/pgtable.h>

#endif
