BITS 32

%define MREMAP_FIXED 2
%define MREMAP_MAYMOVE 1

_start:
	; munmap NULL to start of payload

	mov eax, 91
	mov ebx, 0 ; address
	mov ecx, 0x42424242 ; length
	int 0x80

	; munmap from end of space to 0x80000000
	mov eax, 91
	mov ebx, 0x43434343 ; address
	mov ecx, 0x44444444 ; length
	int 0x80

	; munmap from 0x80000000 to 0xc0000000
	; some linux distros have that as unaccessible, so need to do it
	; separately so that it works

	mov eax, 91
	mov ebx, 0x80000000 ; address
	mov ecx, 0xc0000000 - 0x80000000 ; length
	int 0x80

	mov ebx, 0x45454545
	mov edi, 0x46464646
	mov ebp, 0x47474747
	call remaparea

	mov ebx, 0x48484848
	mov edi, 0x49494949
	mov ebp, 0x4a4a4a4a
	call remaparea

	; restore esp to proper stack location
	pop esp

	; and transfer control :D
	; this approach leaves two pages around :~(
	; but oh well.

	int3
	mov eax, 0x4b4b4b4b
	jmp eax

;
; mremap()'s ebx to edi, for ebp pages.
; trashes ebx, ebp, edi
; 
; this calls mremap() on each page, as it seems that mremap can't handle
; huge ranges with multiple page permissions (some rw, some none, some rx, etc)
; 
; it's a little slow, but we can't rely on /proc/self/maps being present.
;

remaparea:	
	mov ecx, 4096
	mov edx, 4096
	mov esi, MREMAP_FIXED|MREMAP_MAYMOVE

.loop:
	mov eax, 163
	int 0x80
	
	add ebx, 4096
	add edi, 4096

	dec ebp
	jnz .loop

.end:
	ret



