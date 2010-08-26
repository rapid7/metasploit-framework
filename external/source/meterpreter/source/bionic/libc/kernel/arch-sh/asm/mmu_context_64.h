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
#ifndef __ASM_SH_MMU_CONTEXT_64_H
#define __ASM_SH_MMU_CONTEXT_64_H

#include <cpu/registers.h>
#include <asm/cacheflush.h>

#define SR_ASID_MASK 0xffffffffff00ffffULL
#define SR_ASID_SHIFT 16

#define set_TTB(pgd) (mmu_pdtp_cache = (pgd))
#define get_TTB() (mmu_pdtp_cache)

#endif
