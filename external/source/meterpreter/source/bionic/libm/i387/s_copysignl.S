/*
 * Based on code written by J.T. Conklin <jtc@NetBSD.org>.
 * Public domain.
 */

#include <machine/asm.h>
__FBSDID("$FreeBSD: src/lib/msun/i387/s_copysignl.S,v 1.1 2005/04/16 21:12:55 das Exp $")

ENTRY(copysignl)
	movl	24(%esp),%edx
	andl	$0x8000,%edx
	movl	12(%esp),%eax
	andl	$0x7fff,%eax
	orl	%edx,%eax
	movl	%eax,12(%esp)
	fldt	4(%esp)
	ret
