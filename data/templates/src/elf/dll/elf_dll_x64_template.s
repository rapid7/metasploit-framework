; build with:
;   nasm elf_dll_x64_template.s -f bin -o template_x64_linux_dll.bin

BITS 64
org     0
ehdr:
  db    0x7f, "ELF", 2, 1, 1, 0    ; e_ident
  db    0, 0, 0, 0,  0, 0, 0, 0
  dw    3                          ; e_type    = ET_DYN
  dw    62                         ; e_machine = EM_X86_64
  dd    1                          ; e_version = EV_CURRENT
  dq    _start                     ; e_entry   = _start
  dq    phdr - $$                  ; e_phoff
  dd    shdr - $$                  ; e_shoff
  dq    0                          ; e_flags
  dw    ehdrsize                   ; e_ehsize
  dw    phdrsize                   ; e_phentsize
  dw    2                          ; e_phnum
  dw    shentsize                  ; e_shentsize
  dw    2                          ; e_shnum
  dw    1                          ; e_shstrndx
ehdrsize equ  $ - ehdr

phdr:
  dd    1                          ; p_type   = PT_LOAD
  dd    7                          ; p_flags  = rwx
  dq    0                          ; p_offset
  dq    $$                         ; p_vaddr
  dq    $$                         ; p_paddr
  dq    0xDEADBEEF                 ; p_filesz
  dq    0xDEADBEEF                 ; p_memsz
  dq    0x1000                     ; p_align
phdrsize equ  $ - phdr
  dd    2                          ; p_type  = PT_DYNAMIC
  dd    7                          ; p_flags = rwx
  dq    dynsection                 ; p_offset
  dq    dynsection                 ; p_vaddr
  dq    dynsection                 ; p_vaddr
  dq    dynsz                      ; p_filesz
  dq    dynsz                      ; p_memsz
  dq    0x1000                     ; p_align

shdr:
  dd    1                          ; sh_name
  dd    6                          ; sh_type = SHT_DYNAMIC
  dq    0                          ; sh_flags
  dq    dynsection                 ; sh_addr
  dq    dynsection                 ; sh_offset
  dq    dynsz                      ; sh_size
  dd    0                          ; sh_link
  dd    0                          ; sh_info
  dq    8                          ; sh_addralign
  dq    7                          ; sh_entsize
shentsize equ $ - shdr
  dd    0                          ; sh_name
  dd    3                          ; sh_type = SHT_STRTAB
  dq    0                          ; sh_flags
  dq    strtab                     ; sh_addr
  dq    strtab                     ; sh_offset
  dq    strtabsz                   ; sh_size
  dd    0                          ; sh_link
  dd    0                          ; sh_info
  dq    0                          ; sh_addralign
  dq    0                          ; sh_entsize
dynsection:
; DT_INIT
  dq    0x0c
  dq    _start
; DT_STRTAB
  dq    0x05
  dq    strtab
; DT_SYMTAB
  dq    0x06
  dq    strtab
; DT_STRSZ
  dq    0x0a
  dq    0
; DT_SYMENT
  dq    0x0b
  dq    0
; DT_NULL
  dq    0x00
  dq    0
dynsz equ $ - dynsection

strtab:
 db 0
 db 0
strtabsz equ $ - strtab
global _start
_start:

