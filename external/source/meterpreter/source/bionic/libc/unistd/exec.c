/*	$OpenBSD: exec.c,v 1.18 2005/08/08 08:05:34 espie Exp $ */
/*-
 * Copyright (c) 1991, 1993
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <paths.h>
#include <stdarg.h>
#include <alloca.h>

extern char **environ;

int
execl(const char *name, const char *arg, ...)
{
	va_list ap;
	char **argv;
	int n;

	va_start(ap, arg);
	n = 1;
	while (va_arg(ap, char *) != NULL)
		n++;
	va_end(ap);
	argv = alloca((n + 1) * sizeof(*argv));
	if (argv == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	va_start(ap, arg);
	n = 1;
	argv[0] = (char *)arg;
	while ((argv[n] = va_arg(ap, char *)) != NULL)
		n++;
	va_end(ap);
	return (execve(name, argv, environ));
}

int
execle(const char *name, const char *arg, ...)
{
	va_list ap;
	char **argv, **envp;
	int n;

	va_start(ap, arg);
	n = 1;
	while (va_arg(ap, char *) != NULL)
		n++;
	va_end(ap);
	argv = alloca((n + 1) * sizeof(*argv));
	if (argv == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	va_start(ap, arg);
	n = 1;
	argv[0] = (char *)arg;
	while ((argv[n] = va_arg(ap, char *)) != NULL)
		n++;
	envp = va_arg(ap, char **);
	va_end(ap);
	return (execve(name, argv, envp));
}

int
execlp(const char *name, const char *arg, ...)
{
	va_list ap;
	char **argv;
	int n;

	va_start(ap, arg);
	n = 1;
	while (va_arg(ap, char *) != NULL)
		n++;
	va_end(ap);
	argv = alloca((n + 1) * sizeof(*argv));
	if (argv == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	va_start(ap, arg);
	n = 1;
	argv[0] = (char *)arg;
	while ((argv[n] = va_arg(ap, char *)) != NULL)
		n++;
	va_end(ap);
	return (execvp(name, argv));
}

int
execv(const char *name, char * const *argv)
{
	(void)execve(name, argv, environ);
	return (-1);
}

int
execvp(const char *name, char * const *argv)
{
	char **memp;
	int cnt, lp, ln, len;
	char *p;
	int eacces = 0;
	char *bp, *cur, *path, buf[MAXPATHLEN];

	/*
	 * Do not allow null name
	 */
	if (name == NULL || *name == '\0') {
		errno = ENOENT;
		return (-1);
 	}

	/* If it's an absolute or relative path name, it's easy. */
	if (strchr(name, '/')) {
		bp = (char *)name;
		cur = path = NULL;
		goto retry;
	}
	bp = buf;

	/* Get the path we're searching. */
	if (!(path = getenv("PATH")))
		path = _PATH_DEFPATH;
	len = strlen(path) + 1;
	cur = alloca(len);
	if (cur == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	strlcpy(cur, path, len);
	path = cur;
	while ((p = strsep(&cur, ":"))) {
		/*
		 * It's a SHELL path -- double, leading and trailing colons
		 * mean the current directory.
		 */
		if (!*p) {
			p = ".";
			lp = 1;
		} else
			lp = strlen(p);
		ln = strlen(name);

		/*
		 * If the path is too long complain.  This is a possible
		 * security issue; given a way to make the path too long
		 * the user may execute the wrong program.
		 */
		if (lp + ln + 2 > (int)sizeof(buf)) {
			struct iovec iov[3];

			iov[0].iov_base = "execvp: ";
			iov[0].iov_len = 8;
			iov[1].iov_base = p;
			iov[1].iov_len = lp;
			iov[2].iov_base = ": path too long\n";
			iov[2].iov_len = 16;
			(void)writev(STDERR_FILENO, iov, 3);
			continue;
		}
		bcopy(p, buf, lp);
		buf[lp] = '/';
		bcopy(name, buf + lp + 1, ln);
		buf[lp + ln + 1] = '\0';

retry:		(void)execve(bp, argv, environ);
		switch(errno) {
		case E2BIG:
			goto done;
		case EISDIR:
		case ELOOP:
		case ENAMETOOLONG:
		case ENOENT:
			break;
		case ENOEXEC:
			for (cnt = 0; argv[cnt]; ++cnt)
				;
			memp = alloca((cnt + 2) * sizeof(char *));
			if (memp == NULL)
				goto done;
			memp[0] = "sh";
			memp[1] = bp;
			bcopy(argv + 1, memp + 2, cnt * sizeof(char *));
			(void)execve(_PATH_BSHELL, memp, environ);
			goto done;
		case ENOMEM:
			goto done;
		case ENOTDIR:
			break;
		case ETXTBSY:
			/*
			 * We used to retry here, but sh(1) doesn't.
			 */
			goto done;
		case EACCES:
			eacces = 1;
			break;
		default:
			goto done;
		}
	}
	if (eacces)
		errno = EACCES;
	else if (!errno)
		errno = ENOENT;
done:
	return (-1);
}
