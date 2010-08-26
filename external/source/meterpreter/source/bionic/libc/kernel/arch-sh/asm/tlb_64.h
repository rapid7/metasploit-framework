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
#ifndef __ASM_SH_TLB_64_H
#define __ASM_SH_TLB_64_H

#define ITLB_FIXED 0x00000000  
#define ITLB_LAST_VAR_UNRESTRICTED 0x000003F0  

#define DTLB_FIXED 0x00800000  
#define DTLB_LAST_VAR_UNRESTRICTED 0x008003F0  

#ifndef __ASSEMBLY__

#define for_each_dtlb_entry(tlb)   for (tlb = cpu_data->dtlb.first;   tlb <= cpu_data->dtlb.last;   tlb += cpu_data->dtlb.step)

#define for_each_itlb_entry(tlb)   for (tlb = cpu_data->itlb.first;   tlb <= cpu_data->itlb.last;   tlb += cpu_data->itlb.step)

#endif
#endif
