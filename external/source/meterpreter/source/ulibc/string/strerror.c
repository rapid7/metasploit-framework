/*-
 * Copyright (c) 1988, 1993
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
 * 4. Neither the name of the University nor the names of its contributors
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

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)strerror.c	8.1 (Berkeley) 6/4/93";
#endif /* LIBC_SCCS and not lint */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: user/kmacy/releng_7_2_zfs/lib/libc/string/strerror.c 165903 2007-01-09 00:28:16Z imp $");

#if defined(NLS)
#include <nl_types.h>
#endif

#if __XSI_VISIBLE == 0
#undef __XSI_VISIBLE
#define __XSI_VISIBLE 1
#endif

#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#define	UPREFIX		"Unknown error"

/*
 * Define a buffer size big enough to describe a 64-bit signed integer
 * converted to ASCII decimal (19 bytes), with an optional leading sign
 * (1 byte); finally, we get the prefix, delimiter (": ") and a trailing
 * NUL from UPREFIX.
 */
#define	EBUFSIZE	(20 + 2 + sizeof(UPREFIX))

/*
 * Doing this by hand instead of linking with stdio(3) avoids bloat for
 * statically linked binaries.
 */
static void
errstr(int num, char *uprefix, char *buf, size_t len)
{
	char *t;
	unsigned int uerr;
	char tmp[EBUFSIZE];

	t = tmp + sizeof(tmp);
	*--t = '\0';
	uerr = (num >= 0) ? num : -num;
	do {
		*--t = "0123456789"[uerr % 10];
	} while (uerr /= 10);
	if (num < 0)
		*--t = '-';
	*--t = ' ';
	*--t = ':';
	strlcpy(buf, uprefix, len);
	strlcat(buf, t, len);
}

int
strerror_r(int errnum, char *strerrbuf, size_t buflen)
{
	int retval = 0;
#if defined(NLS)
	int saved_errno = errno;
	nl_catd catd;
	catd = catopen("libc", NL_CAT_LOCALE);
#endif

	if (errnum < 1 || errnum >= sys_nerr) {
		errstr(errnum,
#if defined(NLS)
			catgets(catd, 1, 0xffff, UPREFIX),
#else
			UPREFIX,
#endif
			strerrbuf, buflen);
		retval = EINVAL;
	} else {
		if (strlcpy(strerrbuf,
#if defined(NLS)
			catgets(catd, 1, errnum, sys_errlist[errnum]),
#else
			sys_errlist[errnum],
#endif
			buflen) >= buflen)
		retval = ERANGE;
	}

#if defined(NLS)
	catclose(catd);
	errno = saved_errno;
#endif

	return (retval);
}

char *
strerror(int num)
{
	static char ebuf[NL_TEXTMAX];

	if (strerror_r(num, ebuf, sizeof(ebuf)) != 0)
	errno = EINVAL;
	return (ebuf);
}
