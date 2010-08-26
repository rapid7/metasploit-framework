/*	$NetBSD: __res_close.c,v 1.4 2005/09/13 01:44:10 christos Exp $	*/

/*
 * written by matthew green, 22/04/97.
 * public domain.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: __res_close.c,v 1.4 2005/09/13 01:44:10 christos Exp $");
#endif /* LIBC_SCCS and not lint */

#if defined(__indr_reference)
__indr_reference(__res_close, res_close)
#else

#include <sys/types.h>
#include <netinet/in.h>
#include "resolv_private.h"

/* XXX THIS IS A MESS!  SEE <resolv.h> XXX */

#undef res_close
void	res_close(void);

void
res_close(void)
{

	__res_close();
}

#endif
