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
#ifndef _ASM_GENERIC__TLB_H
#define _ASM_GENERIC__TLB_H

#include <linux/swap.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

#define FREE_PTE_NR 1
#define tlb_fast_mode(tlb) 1

struct mmu_gather {
 struct mm_struct *mm;
 unsigned int nr;
 unsigned int need_flush;
 unsigned int fullmm;
 struct page * pages[FREE_PTE_NR];
};

#define tlb_remove_tlb_entry(tlb, ptep, address)   do {   tlb->need_flush = 1;   __tlb_remove_tlb_entry(tlb, ptep, address);   } while (0)
#define pte_free_tlb(tlb, ptep)   do {   tlb->need_flush = 1;   __pte_free_tlb(tlb, ptep);   } while (0)
#ifndef __ARCH_HAS_4LEVEL_HACK
#define pud_free_tlb(tlb, pudp)   do {   tlb->need_flush = 1;   __pud_free_tlb(tlb, pudp);   } while (0)
#endif
#define pmd_free_tlb(tlb, pmdp)   do {   tlb->need_flush = 1;   __pmd_free_tlb(tlb, pmdp);   } while (0)
#define tlb_migrate_finish(mm) do {} while (0)
#endif
