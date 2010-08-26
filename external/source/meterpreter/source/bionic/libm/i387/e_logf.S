/*
 * Written by J.T. Conklin <jtc@netbsd.org>.
 * Public domain.
 */

#include <machine/asm.h>

__FBSDID("$FreeBSD: src/lib/msun/i387/e_logf.S,v 1.2 2005/02/04 14:08:32 das Exp $");
/* RCSID("$NetBSD: e_logf.S,v 1.2 1996/07/06 00:15:45 jtc Exp $") */

ENTRY(logf)
	fldln2
	flds	4(%esp)
	fyl2x
	ret
