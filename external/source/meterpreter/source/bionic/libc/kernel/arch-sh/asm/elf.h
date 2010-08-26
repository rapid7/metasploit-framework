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
#ifndef __ASM_SH_ELF_H
#define __ASM_SH_ELF_H

#include <linux/utsname.h>
#include <asm/auxvec.h>
#include <asm/ptrace.h>
#include <asm/user.h>

#define EF_SH_PIC 0x100  
#define EF_SH_FDPIC 0x8000  

#define R_SH_NONE 0
#define R_SH_DIR32 1
#define R_SH_REL32 2
#define R_SH_DIR8WPN 3
#define R_SH_IND12W 4
#define R_SH_DIR8WPL 5
#define R_SH_DIR8WPZ 6
#define R_SH_DIR8BP 7
#define R_SH_DIR8W 8
#define R_SH_DIR8L 9
#define R_SH_SWITCH16 25
#define R_SH_SWITCH32 26
#define R_SH_USES 27
#define R_SH_COUNT 28
#define R_SH_ALIGN 29
#define R_SH_CODE 30
#define R_SH_DATA 31
#define R_SH_LABEL 32
#define R_SH_SWITCH8 33
#define R_SH_GNU_VTINHERIT 34
#define R_SH_GNU_VTENTRY 35
#define R_SH_TLS_GD_32 144
#define R_SH_TLS_LD_32 145
#define R_SH_TLS_LDO_32 146
#define R_SH_TLS_IE_32 147
#define R_SH_TLS_LE_32 148
#define R_SH_TLS_DTPMOD32 149
#define R_SH_TLS_DTPOFF32 150
#define R_SH_TLS_TPOFF32 151
#define R_SH_GOT32 160
#define R_SH_PLT32 161
#define R_SH_COPY 162
#define R_SH_GLOB_DAT 163
#define R_SH_JMP_SLOT 164
#define R_SH_RELATIVE 165
#define R_SH_GOTOFF 166
#define R_SH_GOTPC 167

#define R_SH_GOT20 70
#define R_SH_GOTOFF20 71
#define R_SH_GOTFUNCDESC 72
#define R_SH_GOTFUNCDESC20 73
#define R_SH_GOTOFFFUNCDESC 74
#define R_SH_GOTOFFFUNCDESC20 75
#define R_SH_FUNCDESC 76
#define R_SH_FUNCDESC_VALUE 77

#define R_SH_IMM_LOW16 246
#define R_SH_IMM_LOW16_PCREL 247
#define R_SH_IMM_MEDLOW16 248
#define R_SH_IMM_MEDLOW16_PCREL 249

#define R_SH_NUM 256

typedef unsigned long elf_greg_t;

#define ELF_NGREG (sizeof (struct pt_regs) / sizeof(elf_greg_t))
typedef elf_greg_t elf_gregset_t[ELF_NGREG];

typedef struct user_fpu_struct elf_fpregset_t;

#define ELF_CLASS ELFCLASS32
#ifdef __LITTLE_ENDIAN__
#define ELF_DATA ELFDATA2LSB
#else
#define ELF_DATA ELFDATA2MSB
#endif
#define ELF_ARCH EM_SH

#endif
