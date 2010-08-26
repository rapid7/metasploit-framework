/*	$OpenBSD: vasprintf.c,v 1.13 2006/01/06 18:53:04 millert Exp $	*/

/*
 * Copyright (c) 1997 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "local.h"

int
vasprintf(char **str, const char *fmt, __va_list ap)
{
	int ret;
	FILE f;
	struct __sfileext fext;
	unsigned char *_base;

	_FILEEXT_SETUP(&f, &fext);
	f._file = -1;
	f._flags = __SWR | __SSTR | __SALC;
	f._bf._base = f._p = (unsigned char *)malloc(128);
	if (f._bf._base == NULL)
		goto err;
	f._bf._size = f._w = 127;		/* Leave room for the NUL */
	ret = vfprintf(&f, fmt, ap);
	if (ret == -1)
		goto err;
	*f._p = '\0';
	_base = realloc(f._bf._base, ret + 1);
	if (_base == NULL)
		goto err;
	*str = (char *)_base;
	return (ret);

err:
	free(f._bf._base);
	*str = NULL;
	errno = ENOMEM;
	return (-1);
}
