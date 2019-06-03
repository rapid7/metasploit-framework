; build with:
;   nasm elf_aarch64_template.s -f bin -o template_aarch64_linux.bin


BITS 64
org     0
ehdr:                            ; Elf32_Ehdr
  db    0x7F, "ELF", 2, 1, 1, 0  ;   e_ident
  db    0, 0, 0, 0,  0, 0, 0, 0  ;
  dw    2                        ;   e_type       = ET_EXEC for an executable
  dw    0xB7                     ;   e_machine    = AARCH64
  dd    0                        ;   e_version
  dq    _start                   ;   e_entry
  dq    phdr - $$                ;   e_phoff
  dq    0                        ;   e_shoff
  dd    0                        ;   e_flags
  dw    ehdrsize                 ;   e_ehsize
  dw    phdrsize                 ;   e_phentsize
  dw    1                        ;   e_phnum
  dw    0                        ;   e_shentsize
  dw    0                        ;   e_shnum
  dw    0                        ;   e_shstrndx

ehdrsize equ  $ - ehdr

phdr:                            ; Elf32_Phdr
  dd    1                        ;   p_type       = PT_LOAD
  dd    7                        ;   p_flags      = rwx
  dq    0                        ;   p_offset
  dq    $$                       ;   p_vaddr
  dq    $$                       ;   p_paddr
  dq    0xDEADBEEF               ;   p_filesz
  dq    0xDEADBEEF               ;   p_memsz
  dq    0x1000                   ;   p_align

phdrsize equ  $ - phdr

global _start

_start:

