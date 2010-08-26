/*	$NetBSD: __res_send.c,v 1.4 2005/09/13 01:44:10 christos Exp $	*/

/*
 * written by matthew green, 22/04/97.
 * public domain.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: __res_send.c,v 1.4 2005/09/13 01:44:10 christos Exp $");
#endif

#if defined(__indr_reference)
__indr_reference(__res_send, res_send)
#else

#include <sys/types.h>
#include <netinet/in.h>
#ifdef ANDROID_CHANGES
#include "resolv_private.h"
#else
#include <resolv.h>
#endif

/* XXX THIS IS A MESS!  SEE <resolv.h> XXX */

#undef res_send
int	res_send(const u_char *, int, u_char *, int);

int
res_send(const u_char *buf, int buflen, u_char *ans, int anssiz)
{

	return __res_send(buf, buflen, ans, anssiz);
}

#endif
