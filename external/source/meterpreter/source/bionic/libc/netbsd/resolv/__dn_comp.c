/*	$NetBSD: __dn_comp.c,v 1.4 2005/09/13 01:44:10 christos Exp $	*/

/*
 * written by matthew green, 22/04/97.
 * public domain.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: __dn_comp.c,v 1.4 2005/09/13 01:44:10 christos Exp $");
#endif /* LIBC_SCCS and not lint */

#if defined(__indr_reference)
__indr_reference(__dn_comp,dn_comp)
#else

#include <sys/types.h>
#include <netinet/in.h>
#ifdef ANDROID_CHANGES
#include "resolv_private.h"
#else
#include <resolv.h>
#endif

/* XXX THIS IS A MESS!  SEE <resolv.h> XXX */

#undef dn_comp
int	dn_comp(const char *, u_char *, int, u_char **, u_char **);

int
dn_comp(const char *exp_dn, u_char *comp_dn, u_char **dnptrs,
    u_char **lastdnptr, int length)
{

	return __dn_comp(exp_dn, comp_dn, length, dnptrs, lastdnptr);
}

#endif
