BITS 64
ehdr:                            ; Elf32_Ehdr
  db    0x7F, "ELF", 2, 2, 1, 0  ;   e_ident
  db    0, 0, 0, 0,  0, 0, 0, 0  ;
  dw    0x0200                   ;   e_type       = ET_EXEC for an executable
  dw    0x1500                   ;   e_machine    = PPC64
  dd    0x01000000                        ;   e_version
  dq    0x7810000000000000      ;   e_entry
  dq    0x4000000000000000       ;   e_phoff
  dq    0                        ;   e_shoff
  dd    0                        ;   e_flags
  dw    0x4000                   ;   e_ehsize
  dw    0x3800                   ;   e_phentsize
  dw    0x0100                   ;   e_phnum
  dw    0                        ;   e_shentsize
  dw    0                        ;   e_shnum
  dw    0                        ;   e_shstrndx

ehdrsize equ  $ - ehdr

phdr:                            ; Elf32_Phdr

  dd    0x01000000               ;   p_type       = pt_load
  dd    0x07000000               ;   p_flags      = rwx
  dq    0                        ;   p_offset
  dq    0x0010000000000000       ;   p_vaddr
  dq    0x0010000000000000                       ;   p_paddr
  dq    0xefbeadde       ;   p_filesz
  dq    0xefbeadde       ;   p_memsz
  dq    0x0000100000000000      ;   p_align

phdrsize equ  $ - phdr

_start:
dq      0x8010000000000000
