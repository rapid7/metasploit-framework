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
#ifndef _LINUX_ELF_H
#define _LINUX_ELF_H

#include <linux/types.h>
#include <linux/auxvec.h>
#include <linux/elf-em.h>
#include <asm/elf.h>

#ifndef elf_read_implies_exec

#define elf_read_implies_exec(ex, have_pt_gnu_stack) 0
#endif

typedef __u32 Elf32_Addr;
typedef __u16 Elf32_Half;
typedef __u32 Elf32_Off;
typedef __s32 Elf32_Sword;
typedef __u32 Elf32_Word;

typedef __u64 Elf64_Addr;
typedef __u16 Elf64_Half;
typedef __s16 Elf64_SHalf;
typedef __u64 Elf64_Off;
typedef __s32 Elf64_Sword;
typedef __u32 Elf64_Word;
typedef __u64 Elf64_Xword;
typedef __s64 Elf64_Sxword;

#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_SHLIB 5
#define PT_PHDR 6
#define PT_TLS 7  
#define PT_LOOS 0x60000000  
#define PT_HIOS 0x6fffffff  
#define PT_LOPROC 0x70000000
#define PT_HIPROC 0x7fffffff
#define PT_GNU_EH_FRAME 0x6474e550

#define PT_GNU_STACK (PT_LOOS + 0x474e551)

#define ET_NONE 0
#define ET_REL 1
#define ET_EXEC 2
#define ET_DYN 3
#define ET_CORE 4
#define ET_LOPROC 0xff00
#define ET_HIPROC 0xffff

#define DT_NULL 0
#define DT_NEEDED 1
#define DT_PLTRELSZ 2
#define DT_PLTGOT 3
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_RELAENT 9
#define DT_STRSZ 10
#define DT_SYMENT 11
#define DT_INIT 12
#define DT_FINI 13
#define DT_SONAME 14
#define DT_RPATH 15
#define DT_SYMBOLIC 16
#define DT_REL 17
#define DT_RELSZ 18
#define DT_RELENT 19
#define DT_PLTREL 20
#define DT_DEBUG 21
#define DT_TEXTREL 22
#define DT_JMPREL 23
#define DT_LOPROC 0x70000000
#define DT_HIPROC 0x7fffffff

#define STB_LOCAL 0
#define STB_GLOBAL 1
#define STB_WEAK 2

#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_SECTION 3
#define STT_FILE 4
#define STT_COMMON 5
#define STT_TLS 6

#define ELF_ST_BIND(x) ((x) >> 4)
#define ELF_ST_TYPE(x) (((unsigned int) x) & 0xf)
#define ELF32_ST_BIND(x) ELF_ST_BIND(x)
#define ELF32_ST_TYPE(x) ELF_ST_TYPE(x)
#define ELF64_ST_BIND(x) ELF_ST_BIND(x)
#define ELF64_ST_TYPE(x) ELF_ST_TYPE(x)

typedef struct dynamic{
 Elf32_Sword d_tag;
 union{
 Elf32_Sword d_val;
 Elf32_Addr d_ptr;
 } d_un;
} Elf32_Dyn;

typedef struct {
 Elf64_Sxword d_tag;
 union {
 Elf64_Xword d_val;
 Elf64_Addr d_ptr;
 } d_un;
} Elf64_Dyn;

#define ELF32_R_SYM(x) ((x) >> 8)
#define ELF32_R_TYPE(x) ((x) & 0xff)

#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i) & 0xffffffff)

typedef struct elf32_rel {
 Elf32_Addr r_offset;
 Elf32_Word r_info;
} Elf32_Rel;

typedef struct elf64_rel {
 Elf64_Addr r_offset;
 Elf64_Xword r_info;
} Elf64_Rel;

typedef struct elf32_rela{
 Elf32_Addr r_offset;
 Elf32_Word r_info;
 Elf32_Sword r_addend;
} Elf32_Rela;

typedef struct elf64_rela {
 Elf64_Addr r_offset;
 Elf64_Xword r_info;
 Elf64_Sxword r_addend;
} Elf64_Rela;

typedef struct elf32_sym{
 Elf32_Word st_name;
 Elf32_Addr st_value;
 Elf32_Word st_size;
 unsigned char st_info;
 unsigned char st_other;
 Elf32_Half st_shndx;
} Elf32_Sym;

typedef struct elf64_sym {
 Elf64_Word st_name;
 unsigned char st_info;
 unsigned char st_other;
 Elf64_Half st_shndx;
 Elf64_Addr st_value;
 Elf64_Xword st_size;
} Elf64_Sym;

#define EI_NIDENT 16

typedef struct elf32_hdr{
 unsigned char e_ident[EI_NIDENT];
 Elf32_Half e_type;
 Elf32_Half e_machine;
 Elf32_Word e_version;
 Elf32_Addr e_entry;
 Elf32_Off e_phoff;
 Elf32_Off e_shoff;
 Elf32_Word e_flags;
 Elf32_Half e_ehsize;
 Elf32_Half e_phentsize;
 Elf32_Half e_phnum;
 Elf32_Half e_shentsize;
 Elf32_Half e_shnum;
 Elf32_Half e_shstrndx;
} Elf32_Ehdr;

typedef struct elf64_hdr {
 unsigned char e_ident[16];
 Elf64_Half e_type;
 Elf64_Half e_machine;
 Elf64_Word e_version;
 Elf64_Addr e_entry;
 Elf64_Off e_phoff;
 Elf64_Off e_shoff;
 Elf64_Word e_flags;
 Elf64_Half e_ehsize;
 Elf64_Half e_phentsize;
 Elf64_Half e_phnum;
 Elf64_Half e_shentsize;
 Elf64_Half e_shnum;
 Elf64_Half e_shstrndx;
} Elf64_Ehdr;

#define PF_R 0x4
#define PF_W 0x2
#define PF_X 0x1

typedef struct elf32_phdr{
 Elf32_Word p_type;
 Elf32_Off p_offset;
 Elf32_Addr p_vaddr;
 Elf32_Addr p_paddr;
 Elf32_Word p_filesz;
 Elf32_Word p_memsz;
 Elf32_Word p_flags;
 Elf32_Word p_align;
} Elf32_Phdr;

typedef struct elf64_phdr {
 Elf64_Word p_type;
 Elf64_Word p_flags;
 Elf64_Off p_offset;
 Elf64_Addr p_vaddr;
 Elf64_Addr p_paddr;
 Elf64_Xword p_filesz;
 Elf64_Xword p_memsz;
 Elf64_Xword p_align;
} Elf64_Phdr;

#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_HASH 5
#define SHT_DYNAMIC 6
#define SHT_NOTE 7
#define SHT_NOBITS 8
#define SHT_REL 9
#define SHT_SHLIB 10
#define SHT_DYNSYM 11
#define SHT_NUM 12
#define SHT_LOPROC 0x70000000
#define SHT_HIPROC 0x7fffffff
#define SHT_LOUSER 0x80000000
#define SHT_HIUSER 0xffffffff

#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4
#define SHF_MASKPROC 0xf0000000

#define SHN_UNDEF 0
#define SHN_LORESERVE 0xff00
#define SHN_LOPROC 0xff00
#define SHN_HIPROC 0xff1f
#define SHN_ABS 0xfff1
#define SHN_COMMON 0xfff2
#define SHN_HIRESERVE 0xffff

typedef struct {
 Elf32_Word sh_name;
 Elf32_Word sh_type;
 Elf32_Word sh_flags;
 Elf32_Addr sh_addr;
 Elf32_Off sh_offset;
 Elf32_Word sh_size;
 Elf32_Word sh_link;
 Elf32_Word sh_info;
 Elf32_Word sh_addralign;
 Elf32_Word sh_entsize;
} Elf32_Shdr;

typedef struct elf64_shdr {
 Elf64_Word sh_name;
 Elf64_Word sh_type;
 Elf64_Xword sh_flags;
 Elf64_Addr sh_addr;
 Elf64_Off sh_offset;
 Elf64_Xword sh_size;
 Elf64_Word sh_link;
 Elf64_Word sh_info;
 Elf64_Xword sh_addralign;
 Elf64_Xword sh_entsize;
} Elf64_Shdr;

#define EI_MAG0 0  
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6
#define EI_OSABI 7
#define EI_PAD 8

#define ELFMAG0 0x7f  
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFMAG "\177ELF"
#define SELFMAG 4

#define ELFCLASSNONE 0  
#define ELFCLASS32 1
#define ELFCLASS64 2
#define ELFCLASSNUM 3

#define ELFDATANONE 0  
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

#define EV_NONE 0  
#define EV_CURRENT 1
#define EV_NUM 2

#define ELFOSABI_NONE 0
#define ELFOSABI_LINUX 3

#ifndef ELF_OSABI
#define ELF_OSABI ELFOSABI_NONE
#endif

#define NT_PRSTATUS 1
#define NT_PRFPREG 2
#define NT_PRPSINFO 3
#define NT_TASKSTRUCT 4
#define NT_AUXV 6
#define NT_PRXFPREG 0x46e62b7f  

typedef struct elf32_note {
 Elf32_Word n_namesz;
 Elf32_Word n_descsz;
 Elf32_Word n_type;
} Elf32_Nhdr;

typedef struct elf64_note {
 Elf64_Word n_namesz;
 Elf64_Word n_descsz;
 Elf64_Word n_type;
} Elf64_Nhdr;

#if ELF_CLASS == ELFCLASS32

#define elfhdr elf32_hdr
#define elf_phdr elf32_phdr
#define elf_note elf32_note

#else

#define elfhdr elf64_hdr
#define elf_phdr elf64_phdr
#define elf_note elf64_note

#endif

#endif
