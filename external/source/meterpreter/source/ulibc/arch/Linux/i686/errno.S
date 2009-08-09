.globl	__errno_location

__errno_location:	
	push	%ebp
	mov	0x0,%eax
	mov	%esp,%ebp
	add	%gs:0x0,%eax
	pop	%ebp
	ret
