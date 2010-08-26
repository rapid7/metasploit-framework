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
#ifndef __ASM_I386_CPUFEATURE_H
#define __ASM_I386_CPUFEATURE_H

#ifndef __ASSEMBLY__
#include <linux/bitops.h>
#endif
#include <asm/required-features.h>

#define NCAPINTS 8  

#define X86_FEATURE_FPU (0*32+ 0)  
#define X86_FEATURE_VME (0*32+ 1)  
#define X86_FEATURE_DE (0*32+ 2)  
#define X86_FEATURE_PSE (0*32+ 3)  
#define X86_FEATURE_TSC (0*32+ 4)  
#define X86_FEATURE_MSR (0*32+ 5)  
#define X86_FEATURE_PAE (0*32+ 6)  
#define X86_FEATURE_MCE (0*32+ 7)  
#define X86_FEATURE_CX8 (0*32+ 8)  
#define X86_FEATURE_APIC (0*32+ 9)  
#define X86_FEATURE_SEP (0*32+11)  
#define X86_FEATURE_MTRR (0*32+12)  
#define X86_FEATURE_PGE (0*32+13)  
#define X86_FEATURE_MCA (0*32+14)  
#define X86_FEATURE_CMOV (0*32+15)  
#define X86_FEATURE_PAT (0*32+16)  
#define X86_FEATURE_PSE36 (0*32+17)  
#define X86_FEATURE_PN (0*32+18)  
#define X86_FEATURE_CLFLSH (0*32+19)  
#define X86_FEATURE_DS (0*32+21)  
#define X86_FEATURE_ACPI (0*32+22)  
#define X86_FEATURE_MMX (0*32+23)  
#define X86_FEATURE_FXSR (0*32+24)  

#define X86_FEATURE_XMM (0*32+25)  
#define X86_FEATURE_XMM2 (0*32+26)  
#define X86_FEATURE_SELFSNOOP (0*32+27)  
#define X86_FEATURE_HT (0*32+28)  
#define X86_FEATURE_ACC (0*32+29)  
#define X86_FEATURE_IA64 (0*32+30)  

#define X86_FEATURE_SYSCALL (1*32+11)  
#define X86_FEATURE_MP (1*32+19)  
#define X86_FEATURE_NX (1*32+20)  
#define X86_FEATURE_MMXEXT (1*32+22)  
#define X86_FEATURE_RDTSCP (1*32+27)  
#define X86_FEATURE_LM (1*32+29)  
#define X86_FEATURE_3DNOWEXT (1*32+30)  
#define X86_FEATURE_3DNOW (1*32+31)  

#define X86_FEATURE_RECOVERY (2*32+ 0)  
#define X86_FEATURE_LONGRUN (2*32+ 1)  
#define X86_FEATURE_LRTI (2*32+ 3)  

#define X86_FEATURE_CXMMX (3*32+ 0)  
#define X86_FEATURE_K6_MTRR (3*32+ 1)  
#define X86_FEATURE_CYRIX_ARR (3*32+ 2)  
#define X86_FEATURE_CENTAUR_MCR (3*32+ 3)  

#define X86_FEATURE_K8 (3*32+ 4)  
#define X86_FEATURE_K7 (3*32+ 5)  
#define X86_FEATURE_P3 (3*32+ 6)  
#define X86_FEATURE_P4 (3*32+ 7)  
#define X86_FEATURE_CONSTANT_TSC (3*32+ 8)  
#define X86_FEATURE_UP (3*32+ 9)  
#define X86_FEATURE_FXSAVE_LEAK (3*32+10)  
#define X86_FEATURE_ARCH_PERFMON (3*32+11)  
#define X86_FEATURE_PEBS (3*32+12)  
#define X86_FEATURE_BTS (3*32+13)  

#define X86_FEATURE_SYNC_RDTSC (3*32+15)  
#define X86_FEATURE_REP_GOOD (3*32+16)  

#define X86_FEATURE_XMM3 (4*32+ 0)  
#define X86_FEATURE_MWAIT (4*32+ 3)  
#define X86_FEATURE_DSCPL (4*32+ 4)  
#define X86_FEATURE_EST (4*32+ 7)  
#define X86_FEATURE_TM2 (4*32+ 8)  
#define X86_FEATURE_CID (4*32+10)  
#define X86_FEATURE_CX16 (4*32+13)  
#define X86_FEATURE_XTPR (4*32+14)  
#define X86_FEATURE_DCA (4*32+18)  

#define X86_FEATURE_XSTORE (5*32+ 2)  
#define X86_FEATURE_XSTORE_EN (5*32+ 3)  
#define X86_FEATURE_XCRYPT (5*32+ 6)  
#define X86_FEATURE_XCRYPT_EN (5*32+ 7)  
#define X86_FEATURE_ACE2 (5*32+ 8)  
#define X86_FEATURE_ACE2_EN (5*32+ 9)  
#define X86_FEATURE_PHE (5*32+ 10)  
#define X86_FEATURE_PHE_EN (5*32+ 11)  
#define X86_FEATURE_PMM (5*32+ 12)  
#define X86_FEATURE_PMM_EN (5*32+ 13)  

#define X86_FEATURE_LAHF_LM (6*32+ 0)  
#define X86_FEATURE_CMP_LEGACY (6*32+ 1)  

#define X86_FEATURE_IDA (7*32+ 0)  

#define cpu_has(c, bit)   (__builtin_constant_p(bit) &&   ( (((bit)>>5)==0 && (1UL<<((bit)&31) & REQUIRED_MASK0)) ||   (((bit)>>5)==1 && (1UL<<((bit)&31) & REQUIRED_MASK1)) ||   (((bit)>>5)==2 && (1UL<<((bit)&31) & REQUIRED_MASK2)) ||   (((bit)>>5)==3 && (1UL<<((bit)&31) & REQUIRED_MASK3)) ||   (((bit)>>5)==4 && (1UL<<((bit)&31) & REQUIRED_MASK4)) ||   (((bit)>>5)==5 && (1UL<<((bit)&31) & REQUIRED_MASK5)) ||   (((bit)>>5)==6 && (1UL<<((bit)&31) & REQUIRED_MASK6)) ||   (((bit)>>5)==7 && (1UL<<((bit)&31) & REQUIRED_MASK7)) )   ? 1 :   test_bit(bit, (c)->x86_capability))
#define boot_cpu_has(bit) cpu_has(&boot_cpu_data, bit)

#define cpu_has_fpu boot_cpu_has(X86_FEATURE_FPU)
#define cpu_has_vme boot_cpu_has(X86_FEATURE_VME)
#define cpu_has_de boot_cpu_has(X86_FEATURE_DE)
#define cpu_has_pse boot_cpu_has(X86_FEATURE_PSE)
#define cpu_has_tsc boot_cpu_has(X86_FEATURE_TSC)
#define cpu_has_pae boot_cpu_has(X86_FEATURE_PAE)
#define cpu_has_pge boot_cpu_has(X86_FEATURE_PGE)
#define cpu_has_apic boot_cpu_has(X86_FEATURE_APIC)
#define cpu_has_sep boot_cpu_has(X86_FEATURE_SEP)
#define cpu_has_mtrr boot_cpu_has(X86_FEATURE_MTRR)
#define cpu_has_mmx boot_cpu_has(X86_FEATURE_MMX)
#define cpu_has_fxsr boot_cpu_has(X86_FEATURE_FXSR)
#define cpu_has_xmm boot_cpu_has(X86_FEATURE_XMM)
#define cpu_has_xmm2 boot_cpu_has(X86_FEATURE_XMM2)
#define cpu_has_xmm3 boot_cpu_has(X86_FEATURE_XMM3)
#define cpu_has_ht boot_cpu_has(X86_FEATURE_HT)
#define cpu_has_mp boot_cpu_has(X86_FEATURE_MP)
#define cpu_has_nx boot_cpu_has(X86_FEATURE_NX)
#define cpu_has_k6_mtrr boot_cpu_has(X86_FEATURE_K6_MTRR)
#define cpu_has_cyrix_arr boot_cpu_has(X86_FEATURE_CYRIX_ARR)
#define cpu_has_centaur_mcr boot_cpu_has(X86_FEATURE_CENTAUR_MCR)
#define cpu_has_xstore boot_cpu_has(X86_FEATURE_XSTORE)
#define cpu_has_xstore_enabled boot_cpu_has(X86_FEATURE_XSTORE_EN)
#define cpu_has_xcrypt boot_cpu_has(X86_FEATURE_XCRYPT)
#define cpu_has_xcrypt_enabled boot_cpu_has(X86_FEATURE_XCRYPT_EN)
#define cpu_has_ace2 boot_cpu_has(X86_FEATURE_ACE2)
#define cpu_has_ace2_enabled boot_cpu_has(X86_FEATURE_ACE2_EN)
#define cpu_has_phe boot_cpu_has(X86_FEATURE_PHE)
#define cpu_has_phe_enabled boot_cpu_has(X86_FEATURE_PHE_EN)
#define cpu_has_pmm boot_cpu_has(X86_FEATURE_PMM)
#define cpu_has_pmm_enabled boot_cpu_has(X86_FEATURE_PMM_EN)
#define cpu_has_ds boot_cpu_has(X86_FEATURE_DS)
#define cpu_has_pebs boot_cpu_has(X86_FEATURE_PEBS)
#define cpu_has_clflush boot_cpu_has(X86_FEATURE_CLFLSH)
#define cpu_has_bts boot_cpu_has(X86_FEATURE_BTS)

#endif

