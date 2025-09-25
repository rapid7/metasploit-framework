; build with:
;   nasm elf_armbe_template.s -f bin -o template_armbe_linux.bin

BITS 32
ehdr:                            ; Elf32_Ehdr
  db    0x7F, "ELF", 1, 2, 1, 0  ;   e_ident
  db    0, 0, 0, 0,  0, 0, 0, 0  ;
  dw    0x0200                   ;   e_type       = ET_EXEC for an executable
  dw    0x2800                   ;   e_machine    = ARM
  dd    0x01000000               ;   e_version
  dd    0x54800000               ;   e_entry
  dd    0x34000000               ;   e_phoff
  dd    0                        ;   e_shoff
  dd    0                        ;   e_flags
  dw    0x3400                   ;   e_ehsize
  dw    0x2000                   ;   e_phentsize
  dw    0x0100                   ;   e_phnum
  dw    0                        ;   e_shentsize
  dw    0                        ;   e_shnum
  dw    0                        ;   e_shstrndx

ehdrsize equ  $ - ehdr

phdr:                            ; Elf32_Phdr

  dd    0x01000000               ;   p_type       = pt_load
  dd    0                        ;   p_offset
  dd    0x00800000               ;   p_vaddr
  dd    0x00800000               ;   p_paddr
  dd    0xefbeadde               ;   p_filesz
  dd    0xefbeadde               ;   p_memsz
  dd    0x07000000               ;   p_flags      = rwx
  dd    0x00100000               ;   p_align

phdrsize equ  $ - phdr

_start:
