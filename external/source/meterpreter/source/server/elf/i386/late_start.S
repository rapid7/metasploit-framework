.globl	call_late_start

call_late_start:
	add	$0x4, %esp
	popl	%eax
	jmp	*%eax
