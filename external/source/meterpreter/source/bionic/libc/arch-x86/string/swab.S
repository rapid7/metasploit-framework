/*	$OpenBSD: swab.S,v 1.3 2005/08/07 11:30:38 espie Exp $ */
/*
 * Written by J.T. Conklin <jtc@netbsd.org>.
 * Public domain.
 */

#include <machine/asm.h>

/*
 * On the i486, this code is negligibly faster than the code generated
 * by gcc at about half the size.  If my i386 databook is correct, it
 * should be considerably faster than the gcc code on a i386.
 */

ENTRY(swab)
	pushl	%esi
	pushl	%edi
	movl	12(%esp),%esi
	movl	16(%esp),%edi
	movl	20(%esp),%ecx

	cld				# set direction forward

	shrl	$1,%ecx
	testl	$7,%ecx			# copy first group of 1 to 7 words
	jz	L2			# while swaping alternate bytes.
	.align	2,0x90
L1:	lodsw
	rorw	$8,%ax
	stosw
	decl	%ecx
	testl	$7,%ecx
	jnz	L1

L2:	shrl	$3,%ecx			# copy remainder 8 words at a time
	jz	L4			# while swapping alternate bytes.
	.align	2,0x90
L3:	lodsw
	rorw	$8,%ax
	stosw
	lodsw
	rorw	$8,%ax
	stosw
	lodsw
	rorw	$8,%ax
	stosw
	lodsw
	rorw	$8,%ax
	stosw
	lodsw
	rorw	$8,%ax
	stosw
	lodsw
	rorw	$8,%ax
	stosw
	lodsw
	rorw	$8,%ax
	stosw
	lodsw
	rorw	$8,%ax
	stosw
	decl	%ecx
	jnz	L3

L4:	popl	%edi
	popl	%esi
	ret
