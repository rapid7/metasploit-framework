; build with:
;   nasm elf_mipsle_template.s -f bin -o template_mipsle_linux.bin

BITS 32

org 0x00400000

ehdr:                            ; Elf32_Ehdr
  db    0x7F, "ELF", 1, 1, 1, 0  ;   e_ident
  db    0, 0, 0, 0,  0, 0, 0, 0  ;
  dw    2                        ;   e_type       = ET_EXEC for an executable
  dw    0x8                      ;   e_machine    = MIPS
  dd    1                        ;   e_version
  dd    _start                   ;   e_entry
  dd    phdr - $$                ;   e_phoff
  dd    0                        ;   e_shoff
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
  dd    0                        ;   p_offset
  dd    $$                       ;   p_vaddr
  dd    $$                       ;   p_paddr
  dd    0xDEADBEEF               ;   p_filesz
  dd    0xDEADBEEF               ;   p_memsz
  dd    7                        ;   p_flags      = rwx
  dd    0x1000                   ;   p_align

phdrsize equ  $ - phdr

_start:

