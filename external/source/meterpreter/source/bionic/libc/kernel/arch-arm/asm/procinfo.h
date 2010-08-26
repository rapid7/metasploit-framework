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
#ifndef __ASM_PROCINFO_H
#define __ASM_PROCINFO_H

#ifndef __ASSEMBLY__

struct cpu_tlb_fns;
struct cpu_user_fns;
struct cpu_cache_fns;
struct processor;

struct proc_info_list {
 unsigned int cpu_val;
 unsigned int cpu_mask;
 unsigned long __cpu_mm_mmu_flags;
 unsigned long __cpu_io_mmu_flags;
 unsigned long __cpu_flush;
 const char *arch_name;
 const char *elf_name;
 unsigned int elf_hwcap;
 const char *cpu_name;
 struct processor *proc;
 struct cpu_tlb_fns *tlb;
 struct cpu_user_fns *user;
 struct cpu_cache_fns *cache;
};

#endif

#define HWCAP_SWP 1
#define HWCAP_HALF 2
#define HWCAP_THUMB 4
#define HWCAP_26BIT 8  
#define HWCAP_FAST_MULT 16
#define HWCAP_FPA 32
#define HWCAP_VFP 64
#define HWCAP_EDSP 128
#define HWCAP_JAVA 256
#define HWCAP_IWMMXT 512

#endif
