/*	$NetBSD: getservent_r.c,v 1.5 2005/04/18 19:39:45 kleink Exp $	*/

/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/types.h>
#include <endian.h>
#include <sys/endian.h>


#if defined(LIBC_SCCS) && !defined(lint)
#if 0
static char sccsid[] = "@(#)getservent.c	8.1 (Berkeley) 6/4/93";
#else
__RCSID("$NetBSD: getservent_r.c,v 1.5 2005/04/18 19:39:45 kleink Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "servent.h"
#include "services.h"


void
setservent_r(int f, struct servent_data *sd)
{
	if (sd->fp == NULL)
		sd->fp = fopen(_PATH_SERVICES, "r");
	else
		rewind(sd->fp);
	sd->stayopen |= f;
}

void
endservent_r(struct servent_data *sd)
{
	if (sd->fp) {
		(void)fclose(sd->fp);
		sd->fp = NULL;
	}
	if (sd->aliases) {
		free(sd->aliases);
		sd->aliases = NULL;
		sd->maxaliases = 0;
	}
	if (sd->line) {
		free(sd->line);
		sd->line = NULL;
	}
	sd->stayopen = 0;
}

struct servent *
getservent_r(struct servent *sp, struct servent_data *sd)
{
	char *p, *cp, **q;
	size_t i = 0;
	int oerrno;

	if (sd->fp == NULL && (sd->fp = fopen(_PATH_SERVICES, "r")) == NULL)
		return NULL;

	for (;;) {
		if (sd->line)
			free(sd->line);
//		sd->line = fparseln(sd->fp, NULL, NULL, NULL, FPARSELN_UNESCALL);
		fprintf(stderr, "*** FIX ME! getservent_r() is going to fail!!!\n");
		sd->line = NULL;
		if (sd->line == NULL)
			return NULL;
		sp->s_name = p = sd->line;
		p = strpbrk(p, " \t");
		if (p == NULL)
			continue;
		*p++ = '\0';
		while (*p == ' ' || *p == '\t')
			p++;
		cp = strpbrk(p, ",/");
		if (cp == NULL)
			continue;
		*cp++ = '\0';
		sp->s_port = htons((u_short)atoi(p));
		sp->s_proto = cp;
		if (sd->aliases == NULL) {
			sd->maxaliases = 10;
			sd->aliases = malloc(sd->maxaliases * sizeof(char *));
			if (sd->aliases == NULL) {
				oerrno = errno;
				endservent_r(sd);
				errno = oerrno;
				return NULL;
			}
		}
		q = sp->s_aliases = sd->aliases;
		cp = strpbrk(cp, " \t");
		if (cp != NULL)
			*cp++ = '\0';
		while (cp && *cp) {
			if (*cp == ' ' || *cp == '\t') {
				cp++;
				continue;
			}
			if (i == sd->maxaliases - 2) {
				sd->maxaliases *= 2;
				q = realloc(q,
				    sd->maxaliases * sizeof(char *));
				if (q == NULL) {
					oerrno = errno;
					endservent_r(sd);
					errno = oerrno;
					return NULL;
				}
				sp->s_aliases = sd->aliases = q;
			}
			q[i++] = cp;
			cp = strpbrk(cp, " \t");
			if (cp != NULL)
				*cp++ = '\0';
		}
		q[i] = NULL;
		return sp;
	}
}
