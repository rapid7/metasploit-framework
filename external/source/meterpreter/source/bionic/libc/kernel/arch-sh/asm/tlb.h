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
#ifndef __ASM_SH_TLB_H
#define __ASM_SH_TLB_H

#ifndef __ASSEMBLY__

#define tlb_start_vma(tlb, vma)   flush_cache_range(vma, vma->vm_start, vma->vm_end)

#define tlb_end_vma(tlb, vma)   flush_tlb_range(vma, vma->vm_start, vma->vm_end)

#define __tlb_remove_tlb_entry(tlb, pte, address) do { } while (0)

#define tlb_flush(tlb) flush_tlb_mm((tlb)->mm)

#include <linux/pagemap.h>
#include <asm-generic/tlb.h>

#endif
#endif
