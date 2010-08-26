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
#ifndef __ASM_SH_PGALLOC_H
#define __ASM_SH_PGALLOC_H

#include <linux/quicklist.h>
#include <asm/page.h>

#define QUICK_PGD 0  
#define QUICK_PT 1  

#define pmd_pgtable(pmd) pmd_page(pmd)
#define __pte_free_tlb(tlb,pte)  do {   pgtable_page_dtor(pte);   tlb_remove_page((tlb), (pte));  } while (0)
#define pmd_free(mm, x) do { } while (0)
#define __pmd_free_tlb(tlb,x) do { } while (0)
#endif
