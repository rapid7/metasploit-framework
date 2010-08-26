/*
 * Written by J.T. Conklin <jtc@netbsd.org>.
 * Public domain.
 */

#include <machine/asm.h>

__FBSDID("$FreeBSD: src/lib/msun/i387/e_scalbf.S,v 1.2 2005/02/04 14:08:32 das Exp $");
/* RCSID("$NetBSD: e_scalbf.S,v 1.1 1996/07/03 16:50:24 jtc Exp $") */

ENTRY(scalbf)
	flds	8(%esp)
	flds	4(%esp)
	fscale
	ret
