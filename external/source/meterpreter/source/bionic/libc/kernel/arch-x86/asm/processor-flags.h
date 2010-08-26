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
#ifndef __ASM_I386_PROCESSOR_FLAGS_H
#define __ASM_I386_PROCESSOR_FLAGS_H

#define X86_EFLAGS_CF 0x00000001  
#define X86_EFLAGS_PF 0x00000004  
#define X86_EFLAGS_AF 0x00000010  
#define X86_EFLAGS_ZF 0x00000040  
#define X86_EFLAGS_SF 0x00000080  
#define X86_EFLAGS_TF 0x00000100  
#define X86_EFLAGS_IF 0x00000200  
#define X86_EFLAGS_DF 0x00000400  
#define X86_EFLAGS_OF 0x00000800  
#define X86_EFLAGS_IOPL 0x00003000  
#define X86_EFLAGS_NT 0x00004000  
#define X86_EFLAGS_RF 0x00010000  
#define X86_EFLAGS_VM 0x00020000  
#define X86_EFLAGS_AC 0x00040000  
#define X86_EFLAGS_VIF 0x00080000  
#define X86_EFLAGS_VIP 0x00100000  
#define X86_EFLAGS_ID 0x00200000  

#define X86_CR0_PE 0x00000001  
#define X86_CR0_MP 0x00000002  
#define X86_CR0_EM 0x00000004  
#define X86_CR0_TS 0x00000008  
#define X86_CR0_ET 0x00000010  
#define X86_CR0_NE 0x00000020  
#define X86_CR0_WP 0x00010000  
#define X86_CR0_AM 0x00040000  
#define X86_CR0_NW 0x20000000  
#define X86_CR0_CD 0x40000000  
#define X86_CR0_PG 0x80000000  

#define X86_CR3_PWT 0x00000008  
#define X86_CR3_PCD 0x00000010  

#define X86_CR4_VME 0x00000001  
#define X86_CR4_PVI 0x00000002  
#define X86_CR4_TSD 0x00000004  
#define X86_CR4_DE 0x00000008  
#define X86_CR4_PSE 0x00000010  
#define X86_CR4_PAE 0x00000020  
#define X86_CR4_MCE 0x00000040  
#define X86_CR4_PGE 0x00000080  
#define X86_CR4_PCE 0x00000100  
#define X86_CR4_OSFXSR 0x00000200  
#define X86_CR4_OSXMMEXCPT 0x00000400  
#define X86_CR4_VMXE 0x00002000  

#define X86_CR8_TPR 0x0000000F  

#define CX86_PCR0 0x20
#define CX86_GCR 0xb8
#define CX86_CCR0 0xc0
#define CX86_CCR1 0xc1
#define CX86_CCR2 0xc2
#define CX86_CCR3 0xc3
#define CX86_CCR4 0xe8
#define CX86_CCR5 0xe9
#define CX86_CCR6 0xea
#define CX86_CCR7 0xeb
#define CX86_PCR1 0xf0
#define CX86_DIR0 0xfe
#define CX86_DIR1 0xff
#define CX86_ARR_BASE 0xc4
#define CX86_RCR_BASE 0xdc

#endif
