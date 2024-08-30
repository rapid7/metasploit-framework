;-----------------------------------------------------------------------------;
; Author: Diego Ledda (diego_ledda[at]rapid7[dot]com)
; Compatible: Windows 11, 10, 7, Vista
; Architecture: x64
; Version: 0.1 (August 2024)
;-----------------------------------------------------------------------------;
; Simple Heaven's Gate implementation that can be put on top of an x86 shellcode.
[BITS 64]
[ORG 0]
x64tox86:
    cld                      ;
    xor rcx,rcx
    mov ecx, 02bh
    mov ss, cx           
    call heavens_gate            
heavens_gate:
    mov dword [esp + 4], 023h  
    add dword [esp], 0fh         
    retf
; From here is executed in x86 bit