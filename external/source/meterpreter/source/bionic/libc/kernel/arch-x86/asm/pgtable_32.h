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
#ifndef _I386_PGTABLE_H
#define _I386_PGTABLE_H

#ifndef __ASSEMBLY__
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <linux/threads.h>
#include <asm/paravirt.h>

#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>

struct mm_struct;
struct vm_area_struct;

#define ZERO_PAGE(vaddr) (virt_to_page(empty_zero_page))

#include <asm/pgtable-2level-defs.h>

#define PGDIR_SIZE (1UL << PGDIR_SHIFT)
#define PGDIR_MASK (~(PGDIR_SIZE-1))

#define USER_PTRS_PER_PGD (TASK_SIZE/PGDIR_SIZE)
#define FIRST_USER_ADDRESS 0

#define USER_PGD_PTRS (PAGE_OFFSET >> PGDIR_SHIFT)
#define KERNEL_PGD_PTRS (PTRS_PER_PGD-USER_PGD_PTRS)

#define TWOLEVEL_PGDIR_SHIFT 22
#define BOOT_USER_PGD_PTRS (__PAGE_OFFSET >> TWOLEVEL_PGDIR_SHIFT)
#define BOOT_KERNEL_PGD_PTRS (1024-BOOT_USER_PGD_PTRS)

#define VMALLOC_OFFSET (8*1024*1024)
#define VMALLOC_START (((unsigned long) high_memory +   2*VMALLOC_OFFSET-1) & ~(VMALLOC_OFFSET-1))
#define VMALLOC_END (FIXADDR_START-2*PAGE_SIZE)

#define _PAGE_BIT_PRESENT 0
#define _PAGE_BIT_RW 1
#define _PAGE_BIT_USER 2
#define _PAGE_BIT_PWT 3
#define _PAGE_BIT_PCD 4
#define _PAGE_BIT_ACCESSED 5
#define _PAGE_BIT_DIRTY 6
#define _PAGE_BIT_PSE 7  
#define _PAGE_BIT_GLOBAL 8  
#define _PAGE_BIT_UNUSED1 9  
#define _PAGE_BIT_UNUSED2 10
#define _PAGE_BIT_UNUSED3 11
#define _PAGE_BIT_NX 63

#define _PAGE_PRESENT 0x001
#define _PAGE_RW 0x002
#define _PAGE_USER 0x004
#define _PAGE_PWT 0x008
#define _PAGE_PCD 0x010
#define _PAGE_ACCESSED 0x020
#define _PAGE_DIRTY 0x040
#define _PAGE_PSE 0x080  
#define _PAGE_GLOBAL 0x100  
#define _PAGE_UNUSED1 0x200  
#define _PAGE_UNUSED2 0x400
#define _PAGE_UNUSED3 0x800

#define _PAGE_FILE 0x040  
#define _PAGE_PROTNONE 0x080  
#define _PAGE_NX 0

#define _PAGE_TABLE (_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED | _PAGE_DIRTY)
#define _KERNPG_TABLE (_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED | _PAGE_DIRTY)
#define _PAGE_CHG_MASK (PTE_MASK | _PAGE_ACCESSED | _PAGE_DIRTY)

#define PAGE_NONE   __pgprot(_PAGE_PROTNONE | _PAGE_ACCESSED)
#define PAGE_SHARED   __pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED)

#define PAGE_SHARED_EXEC   __pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED)
#define PAGE_COPY_NOEXEC   __pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED | _PAGE_NX)
#define PAGE_COPY_EXEC   __pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED)
#define PAGE_COPY   PAGE_COPY_NOEXEC
#define PAGE_READONLY   __pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED | _PAGE_NX)
#define PAGE_READONLY_EXEC   __pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED)

#define _PAGE_KERNEL   (_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_NX)
#define _PAGE_KERNEL_EXEC   (_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED)

#define __PAGE_KERNEL_RO (__PAGE_KERNEL & ~_PAGE_RW)
#define __PAGE_KERNEL_RX (__PAGE_KERNEL_EXEC & ~_PAGE_RW)
#define __PAGE_KERNEL_NOCACHE (__PAGE_KERNEL | _PAGE_PCD)
#define __PAGE_KERNEL_LARGE (__PAGE_KERNEL | _PAGE_PSE)
#define __PAGE_KERNEL_LARGE_EXEC (__PAGE_KERNEL_EXEC | _PAGE_PSE)

#define PAGE_KERNEL __pgprot(__PAGE_KERNEL)
#define PAGE_KERNEL_RO __pgprot(__PAGE_KERNEL_RO)
#define PAGE_KERNEL_EXEC __pgprot(__PAGE_KERNEL_EXEC)
#define PAGE_KERNEL_RX __pgprot(__PAGE_KERNEL_RX)
#define PAGE_KERNEL_NOCACHE __pgprot(__PAGE_KERNEL_NOCACHE)
#define PAGE_KERNEL_LARGE __pgprot(__PAGE_KERNEL_LARGE)
#define PAGE_KERNEL_LARGE_EXEC __pgprot(__PAGE_KERNEL_LARGE_EXEC)

#define __P000 PAGE_NONE
#define __P001 PAGE_READONLY
#define __P010 PAGE_COPY
#define __P011 PAGE_COPY
#define __P100 PAGE_READONLY_EXEC
#define __P101 PAGE_READONLY_EXEC
#define __P110 PAGE_COPY_EXEC
#define __P111 PAGE_COPY_EXEC

#define __S000 PAGE_NONE
#define __S001 PAGE_READONLY
#define __S010 PAGE_SHARED
#define __S011 PAGE_SHARED
#define __S100 PAGE_READONLY_EXEC
#define __S101 PAGE_READONLY_EXEC
#define __S110 PAGE_SHARED_EXEC
#define __S111 PAGE_SHARED_EXEC

#undef TEST_ACCESS_OK

#define pte_present(x) ((x).pte_low & (_PAGE_PRESENT | _PAGE_PROTNONE))

#define pmd_none(x) (!(unsigned long)pmd_val(x))
#define pmd_present(x) (pmd_val(x) & _PAGE_PRESENT)
#define pmd_bad(x) ((pmd_val(x) & (~PAGE_MASK & ~_PAGE_USER)) != _KERNPG_TABLE)

#define pages_to_mb(x) ((x) >> (20-PAGE_SHIFT))

#include <asm/pgtable-2level.h>
#define pte_update(mm, addr, ptep) do { } while (0)
#define pte_update_defer(mm, addr, ptep) do { } while (0)
#define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
#define ptep_set_access_flags(vma, address, ptep, entry, dirty)  ({   int __changed = !pte_same(*(ptep), entry);   if (__changed && dirty) {   (ptep)->pte_low = (entry).pte_low;   pte_update_defer((vma)->vm_mm, (address), (ptep));   flush_tlb_page(vma, address);   }   __changed;  })
#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
#define ptep_test_and_clear_young(vma, addr, ptep) ({   int __ret = 0;   if (pte_young(*(ptep)))   __ret = test_and_clear_bit(_PAGE_BIT_ACCESSED,   &(ptep)->pte_low);   if (__ret)   pte_update((vma)->vm_mm, addr, ptep);   __ret;  })
#define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
#define ptep_clear_flush_young(vma, address, ptep)  ({   int __young;   __young = ptep_test_and_clear_young((vma), (address), (ptep));   if (__young)   flush_tlb_page(vma, address);   __young;  })
#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
#define __HAVE_ARCH_PTEP_GET_AND_CLEAR_FULL
#define __HAVE_ARCH_PTEP_SET_WRPROTECT
#define pgprot_noncached(prot) ((boot_cpu_data.x86 > 3)   ? (__pgprot(pgprot_val(prot) | _PAGE_PCD | _PAGE_PWT)) : (prot))
#define mk_pte(page, pgprot) pfn_pte(page_to_pfn(page), (pgprot))
#define pmd_large(pmd)  ((pmd_val(pmd) & (_PAGE_PSE|_PAGE_PRESENT)) == (_PAGE_PSE|_PAGE_PRESENT))
#define pgd_index(address) (((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD-1))
#define pgd_index_k(addr) pgd_index(addr)
#define pgd_offset(mm, address) ((mm)->pgd+pgd_index(address))
#define pgd_offset_k(address) pgd_offset(&init_mm, address)
#define pmd_index(address)   (((address) >> PMD_SHIFT) & (PTRS_PER_PMD-1))
#define pte_index(address)   (((address) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
#define pte_offset_kernel(dir, address)   ((pte_t *) pmd_page_vaddr(*(dir)) + pte_index(address))
#define pmd_page(pmd) (pfn_to_page(pmd_val(pmd) >> PAGE_SHIFT))
#define pmd_page_vaddr(pmd)   ((unsigned long) __va(pmd_val(pmd) & PAGE_MASK))

 #define pte_offset_map(dir, address)   ((pte_t *)page_address(pmd_page(*(dir))) + pte_index(address))
#define pte_offset_map_nested(dir, address) pte_offset_map(dir, address)
#define pte_unmap(pte) do { } while (0)
#define pte_unmap_nested(pte) do { } while (0)
#define kpte_clear_flush(ptep, vaddr)  do {   pte_clear(&init_mm, vaddr, ptep);   __flush_tlb_one(vaddr);  } while (0)
#define update_mmu_cache(vma,address,pte) do { } while (0)

#endif
#define io_remap_pfn_range(vma, vaddr, pfn, size, prot)   remap_pfn_range(vma, vaddr, pfn, size, prot)
#include <asm-generic/pgtable.h>
#endif
