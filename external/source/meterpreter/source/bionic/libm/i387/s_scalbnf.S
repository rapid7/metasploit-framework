/*
 * Written by J.T. Conklin <jtc@netbsd.org>.
 * Public domain.
 */

#include <machine/asm.h>

__FBSDID("$FreeBSD: src/lib/msun/i387/s_scalbnf.S,v 1.2 2005/03/07 04:52:43 das Exp $");
/* RCSID("$NetBSD: s_scalbnf.S,v 1.4 1999/01/02 05:15:40 kristerw Exp $") */

ENTRY(scalbnf)
	fildl	8(%esp)
	flds	4(%esp)
	fscale
	fstp	%st(1)		/* bug fix for fp stack overflow */
	ret

.globl CNAME(ldexpf)
.set	CNAME(ldexpf),CNAME(scalbnf)
