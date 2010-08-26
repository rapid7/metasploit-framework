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
#ifndef _ASM_X86_ELF_H
#define _ASM_X86_ELF_H

#include <asm/ptrace.h>
#include <asm/user.h>
#include <asm/auxvec.h>

typedef unsigned long elf_greg_t;

#define ELF_NGREG (sizeof (struct user_regs_struct) / sizeof(elf_greg_t))
typedef elf_greg_t elf_gregset_t[ELF_NGREG];

typedef struct user_i387_struct elf_fpregset_t;

#ifdef __i386__

typedef struct user_fxsr_struct elf_fpxregset_t;

#define R_386_NONE 0
#define R_386_32 1
#define R_386_PC32 2
#define R_386_GOT32 3
#define R_386_PLT32 4
#define R_386_COPY 5
#define R_386_GLOB_DAT 6
#define R_386_JMP_SLOT 7
#define R_386_RELATIVE 8
#define R_386_GOTOFF 9
#define R_386_GOTPC 10
#define R_386_NUM 11

#define ELF_CLASS ELFCLASS32
#define ELF_DATA ELFDATA2LSB
#define ELF_ARCH EM_386

#else

#define R_X86_64_NONE 0  
#define R_X86_64_64 1  
#define R_X86_64_PC32 2  
#define R_X86_64_GOT32 3  
#define R_X86_64_PLT32 4  
#define R_X86_64_COPY 5  
#define R_X86_64_GLOB_DAT 6  
#define R_X86_64_JUMP_SLOT 7  
#define R_X86_64_RELATIVE 8  
#define R_X86_64_GOTPCREL 9  
#define R_X86_64_32 10  
#define R_X86_64_32S 11  
#define R_X86_64_16 12  
#define R_X86_64_PC16 13  
#define R_X86_64_8 14  
#define R_X86_64_PC8 15  

#define R_X86_64_NUM 16

#define ELF_CLASS ELFCLASS64
#define ELF_DATA ELFDATA2LSB
#define ELF_ARCH EM_X86_64

#endif

#endif
