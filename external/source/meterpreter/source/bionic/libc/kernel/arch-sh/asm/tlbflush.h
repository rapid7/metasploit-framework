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
#ifndef __ASM_SH_TLBFLUSH_H
#define __ASM_SH_TLBFLUSH_H

#define flush_tlb_all() local_flush_tlb_all()
#define flush_tlb_mm(mm) local_flush_tlb_mm(mm)
#define flush_tlb_page(vma, page) local_flush_tlb_page(vma, page)
#define flush_tlb_one(asid, page) local_flush_tlb_one(asid, page)

#define flush_tlb_range(vma, start, end)   local_flush_tlb_range(vma, start, end)

#define flush_tlb_kernel_range(start, end)   local_flush_tlb_kernel_range(start, end)

#endif
