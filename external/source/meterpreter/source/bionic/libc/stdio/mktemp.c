/*	$OpenBSD: mktemp.c,v 1.19 2005/08/08 08:05:36 espie Exp $ */
/*
 * Copyright (c) 1987, 1993
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

static int _gettemp(char *, int *, int, int);

extern uint32_t  arc4random();

int
mkstemps(char *path, int slen)
{
	int fd;

	return (_gettemp(path, &fd, 0, slen) ? fd : -1);
}

int
mkstemp(char *path)
{
	int fd;

	return (_gettemp(path, &fd, 0, 0) ? fd : -1);
}

char *
mkdtemp(char *path)
{
	return(_gettemp(path, (int *)NULL, 1, 0) ? path : (char *)NULL);
}

char *_mktemp(char *);

char *
_mktemp(char *path)
{
	return(_gettemp(path, (int *)NULL, 0, 0) ? path : (char *)NULL);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

char *
mktemp(char *path)
{
	return(_mktemp(path));
}


static int
_gettemp(char *path, int *doopen, int domkdir, int slen)
{
	char *start, *trv, *suffp;
	struct stat sbuf;
	int rval;
	pid_t pid;

	if (doopen && domkdir) {
		errno = EINVAL;
		return(0);
	}

	for (trv = path; *trv; ++trv)
		;
	trv -= slen;
	suffp = trv;
	--trv;
	if (trv < path) {
		errno = EINVAL;
		return (0);
	}
	pid = getpid();
	while (trv >= path && *trv == 'X' && pid != 0) {
		*trv-- = (pid % 10) + '0';
		pid /= 10;
	}
	while (trv >= path && *trv == 'X') {
		char c;

		pid = (arc4random() & 0xffff) % (26+26);
		if (pid < 26)
			c = pid + 'A';
		else
			c = (pid - 26) + 'a';
		*trv-- = c;
	}
	start = trv + 1;

	/*
	 * check the target directory; if you have six X's and it
	 * doesn't exist this runs for a *very* long time.
	 */
	if (doopen || domkdir) {
		for (;; --trv) {
			if (trv <= path)
				break;
			if (*trv == '/') {
				*trv = '\0';
				rval = stat(path, &sbuf);
				*trv = '/';
				if (rval != 0)
					return(0);
				if (!S_ISDIR(sbuf.st_mode)) {
					errno = ENOTDIR;
					return(0);
				}
				break;
			}
		}
	}

	for (;;) {
		if (doopen) {
			if ((*doopen =
			    open(path, O_CREAT|O_EXCL|O_RDWR, 0600)) >= 0)
				return(1);
			if (errno != EEXIST)
				return(0);
		} else if (domkdir) {
			if (mkdir(path, 0700) == 0)
				return(1);
			if (errno != EEXIST)
				return(0);
		} else if (lstat(path, &sbuf))
			return(errno == ENOENT ? 1 : 0);

		/* tricky little algorithm for backward compatibility */
		for (trv = start;;) {
			if (!*trv)
				return (0);
			if (*trv == 'Z') {
				if (trv == suffp)
					return (0);
				*trv++ = 'a';
			} else {
				if (isdigit(*trv))
					*trv = 'a';
				else if (*trv == 'z')	/* inc from z to A */
					*trv = 'A';
				else {
					if (trv == suffp)
						return (0);
					++*trv;
				}
				break;
			}
		}
	}
	/*NOTREACHED*/
}
