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
#ifndef __ASMARM_ELF_H
#define __ASMARM_ELF_H

#include <asm/ptrace.h>
#include <asm/user.h>
#ifdef __KERNEL
#include <asm/procinfo.h>
#endif

typedef unsigned long elf_greg_t;
typedef unsigned long elf_freg_t[3];

#define EM_ARM 40
#define EF_ARM_APCS26 0x08
#define EF_ARM_SOFT_FLOAT 0x200
#define EF_ARM_EABI_MASK 0xFF000000

#define R_ARM_NONE 0
#define R_ARM_PC24 1
#define R_ARM_ABS32 2
#define R_ARM_CALL 28
#define R_ARM_JUMP24 29

#define ELF_NGREG (sizeof (struct pt_regs) / sizeof(elf_greg_t))
typedef elf_greg_t elf_gregset_t[ELF_NGREG];

typedef struct user_fp elf_fpregset_t;

#define elf_check_arch(x) ( ((x)->e_machine == EM_ARM) && (ELF_PROC_OK((x))) )

#define ELF_CLASS ELFCLASS32
#ifdef __ARMEB__
#define ELF_DATA ELFDATA2MSB
#else
#define ELF_DATA ELFDATA2LSB
#endif
#define ELF_ARCH EM_ARM

#define USE_ELF_CORE_DUMP
#define ELF_EXEC_PAGESIZE 4096

#define ELF_ET_DYN_BASE (2 * TASK_SIZE / 3)

#define ELF_PLAT_INIT(_r, load_addr) (_r)->ARM_r0 = 0

#define ELF_HWCAP (elf_hwcap)

#define ELF_PLATFORM_SIZE 8

#define ELF_PLATFORM (elf_platform)

#endif
