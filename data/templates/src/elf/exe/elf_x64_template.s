; build with:
;   nasm elf_x64_template.s -f bin -o template_x64_linux.bin

BITS 64

org 0x0000000000400000

ehdr:                            ; Elf64_Ehdr
  db    0x7F, "ELF", 2, 1, 1, 0  ;   e_ident
  db    0, 0, 0, 0,  0, 0, 0, 0  ;
  dw    2                        ;   e_type       = ET_EXEC for an executable
  dw    0x3e                     ;   e_machine
  dd    1                        ;   e_version
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

phdr:                            ; Elf64_Phdr
  dd    1                        ;   p_type       = PT_LOAD
  dd    7                        ;   p_flags      = rwx
  dq    0                        ;   p_offset
  dq    $$                       ;   p_vaddr
  dq    $$                       ;   p_paddr
  dq    0x4141414141414141       ;   p_filesz
  dq    0x4242424242424242       ;   p_memsz
  dq    0x1000                   ;   p_align

phdrsize equ  $ - phdr

global _start

_start:

