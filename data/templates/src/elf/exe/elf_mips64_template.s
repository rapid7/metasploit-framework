; build with:
;   nasm elf_mips64_template.s -f bin -o template_mips64_linux.bin

%define WORD_BE(value) (((value & 0xFF) << 8) | ((value >> 8) & 0xFF))
%define DWORD_BE(dword) (((dword & 0xFF) << 24) | \
                        ((dword & 0xFF00) << 8) | \
                        ((dword >> 8) & 0xFF00) | \
                        ((dword >> 24) & 0xFF))
%define QWORD_BE(qword) ( \
    ((qword & 0x00000000000000FF) << 56) | \
    ((qword & 0x000000000000FF00) << 40) | \
    ((qword & 0x0000000000FF0000) << 24) | \
    ((qword & 0x00000000FF000000) << 8) | \
    ((qword >> 8) & 0x000000FF00000000) | \
    ((qword >> 24) & 0x0000FF0000000000) | \
    ((qword >> 40) & 0x00FF000000000000) | \
    ((qword >> 56) & 0xFF00000000000000) )

BITS 64

org     0x400000
ehdr:                            ; Elf32_Ehdr
  db    0x7F, "ELF", 2, 2, 1, 0  ;   e_ident
  db    0, 0, 0, 0,  0, 0, 0, 0  ;
  dw    WORD_BE(2)               ;   e_type       = ET_EXEC for an executable
  dw    WORD_BE(0x08)            ;   e_machine    = MIPS
  dd    0                        ;   e_version
  dq    QWORD_BE(0x400078)       ;   e_entry
  dq    QWORD_BE(0x40)           ;   e_phoff
  dq    0                        ;   e_shoff
  dd    0                        ;   e_flags
  dw    WORD_BE(0x40)            ;   e_ehsize
  dw    WORD_BE(0x38)            ;   e_phentsize
  dw    WORD_BE(0x1)             ;   e_phnum
  dw    0                        ;   e_shentsize
  dw    0                        ;   e_shnum
  dw    0                        ;   e_shstrndx

ehdrsize equ  $ - ehdr

phdr:                            ; Elf32_Phdr
  dd    DWORD_BE(1)              ;   p_type       = PT_LOAD
  dd    DWORD_BE(7)              ;   p_flags      = rwx
  dq    0                        ;   p_offset
  dq    QWORD_BE(0x400000)       ;   p_vaddr
  dq    QWORD_BE(0x400000)       ;   p_paddr
  dq    QWORD_BE(0xA00000)       ;   p_filesz
  dq    QWORD_BE(0xA00000)       ;   p_memsz
  dq    QWORD_BE(0x1000)         ;   p_align

phdrsize equ  $ - phdr

global _start

_start:
