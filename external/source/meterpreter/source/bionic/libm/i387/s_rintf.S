/*
 * Written by J.T. Conklin <jtc@netbsd.org>.
 * Public domain.
 */

#include <machine/asm.h>

__FBSDID("$FreeBSD: src/lib/msun/i387/s_rintf.S,v 1.1 2005/01/13 18:58:25 das Exp $");
/* RCSID("$NetBSD: s_rintf.S,v 1.3 1995/05/09 00:17:22 jtc Exp $") */

ENTRY(rintf)
	flds	4(%esp)
	frndint
	ret
