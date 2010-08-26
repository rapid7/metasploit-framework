/*	$OpenBSD: err.h,v 1.10 2006/01/06 18:53:04 millert Exp $	*/
/*	$NetBSD: err.h,v 1.11 1994/10/26 00:55:52 cgd Exp $	*/

/*-
 * Copyright (c) 1993
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
 *
 *	@(#)err.h	8.1 (Berkeley) 6/2/93
 */

#ifndef _ERR_H_
#define	_ERR_H_

/*
 * Don't use va_list in the err/warn prototypes.   Va_list is typedef'd in two
 * places (<machine/varargs.h> and <machine/stdarg.h>), so if we include one
 * of them here we may collide with the utility's includes.  It's unreasonable
 * for utilities to have to include one of them to include err.h, so we get
 * __va_list from <machine/_types.h> and use it.
 */
#include <sys/cdefs.h>
#include <machine/_types.h>

__BEGIN_DECLS

__noreturn void	err(int, const char *, ...)
			__attribute__((__format__ (printf, 2, 3)));
__noreturn void	verr(int, const char *, __va_list)
			__attribute__((__format__ (printf, 2, 0)));
__noreturn void	errx(int, const char *, ...)
			__attribute__((__format__ (printf, 2, 3)));
__noreturn void	verrx(int, const char *, __va_list)
			__attribute__((__format__ (printf, 2, 0)));
void		warn(const char *, ...)
			__attribute__((__format__ (printf, 1, 2)));
void		vwarn(const char *, __va_list)
			__attribute__((__format__ (printf, 1, 0)));
void		warnx(const char *, ...)
			__attribute__((__format__ (printf, 1, 2)));
void		vwarnx(const char *, __va_list)
			__attribute__((__format__ (printf, 1, 0)));

/*
 * The _* versions are for use in library functions so user-defined
 * versions of err*,warn* do not get used.
 */
__noreturn void	_err(int, const char *, ...)
			__attribute__((__format__ (printf, 2, 3)));
__noreturn void	_verr(int, const char *, __va_list)
			__attribute__((__format__ (printf, 2, 0)));
__noreturn void	_errx(int, const char *, ...)
			__attribute__((__format__ (printf, 2, 3)));
__noreturn void	_verrx(int, const char *, __va_list)
			__attribute__((__format__ (printf, 2, 0)));
void		_warn(const char *, ...)
			__attribute__((__format__ (printf, 1, 2)));
void		_vwarn(const char *, __va_list)
			__attribute__((__format__ (printf, 1, 0)));
void		_warnx(const char *, ...)
			__attribute__((__format__ (printf, 1, 2)));
void		_vwarnx(const char *, __va_list)
			__attribute__((__format__ (printf, 1, 0)));

__END_DECLS

#endif /* !_ERR_H_ */
