/*	$OpenBSD: ffs.S,v 1.3 2005/08/07 11:30:38 espie Exp $ */
/*
 * Written by J.T. Conklin <jtc@netbsd.org>.
 * Public domain.
 */

#include <machine/asm.h>

ENTRY(ffs)
	bsfl	4(%esp),%eax
	jz	L1	 		/* ZF is set if all bits are 0 */
	incl	%eax			/* bits numbered from 1, not 0 */
	ret

	.align 2
L1:	xorl	%eax,%eax		/* clear result */
	ret
