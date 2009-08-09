/*-
 * Copyright (c)1999 Citrus Project,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: head/include/wchar.h 189365 2009-03-04 15:45:34Z das $
 */

/*-
 * Copyright (c) 1999, 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Julian Coleman.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *	$NetBSD: wchar.h,v 1.8 2000/12/22 05:31:42 itojun Exp $
 */

#ifndef _WCHAR_H_
#define _WCHAR_H_

#include <sys/cdefs.h>
#include <sys/_null.h>
#include <sys/_types.h>
#include <machine/_limits.h>
#include <_ctype.h>

#ifndef _MBSTATE_T_DECLARED
typedef	__mbstate_t	mbstate_t;
#define	_MBSTATE_T_DECLARED
#endif

#ifndef _SIZE_T_DECLARED
typedef	__size_t	size_t;
#define	_SIZE_T_DECLARED
#endif

#ifndef	__cplusplus
#ifndef _WCHAR_T_DECLARED
typedef	__wchar_t	wchar_t;
#define	_WCHAR_T_DECLARED
#endif
#endif

#ifndef _WINT_T_DECLARED
typedef	__wint_t	wint_t;
#define	_WINT_T_DECLARED
#endif

#ifndef	WCHAR_MIN 
#define	WCHAR_MIN	__INT_MIN
#define	WCHAR_MAX	__INT_MAX
#endif

#ifndef WEOF
#define	WEOF 	((wint_t)-1)
#endif

struct __sFILE;
struct tm;

__BEGIN_DECLS
wint_t	btowc(int);
wint_t	fgetwc(struct __sFILE *);
wchar_t	*
	fgetws(wchar_t * __restrict, int, struct __sFILE * __restrict);
wint_t	fputwc(wchar_t, struct __sFILE *);
int	fputws(const wchar_t * __restrict, struct __sFILE * __restrict);
int	fwide(struct __sFILE *, int);
int	fwprintf(struct __sFILE * __restrict, const wchar_t * __restrict, ...);
int	fwscanf(struct __sFILE * __restrict, const wchar_t * __restrict, ...);
wint_t	getwc(struct __sFILE *);
wint_t	getwchar(void);
size_t	mbrlen(const char * __restrict, size_t, mbstate_t * __restrict);
size_t	mbrtowc(wchar_t * __restrict, const char * __restrict, size_t,
	    mbstate_t * __restrict);
int	mbsinit(const mbstate_t *);
size_t	mbsrtowcs(wchar_t * __restrict, const char ** __restrict, size_t,
	    mbstate_t * __restrict);
wint_t	putwc(wchar_t, struct __sFILE *);
wint_t	putwchar(wchar_t);
int	swprintf(wchar_t * __restrict, size_t n, const wchar_t * __restrict,
	    ...);
int	swscanf(const wchar_t * __restrict, const wchar_t * __restrict, ...);
wint_t	ungetwc(wint_t, struct __sFILE *);
int	vfwprintf(struct __sFILE * __restrict, const wchar_t * __restrict,
	    __va_list);
int	vswprintf(wchar_t * __restrict, size_t n, const wchar_t * __restrict,
	    __va_list);
int	vwprintf(const wchar_t * __restrict, __va_list);
size_t	wcrtomb(char * __restrict, wchar_t, mbstate_t * __restrict);
wchar_t	*wcscat(wchar_t * __restrict, const wchar_t * __restrict);
wchar_t	*wcschr(const wchar_t *, wchar_t) __pure;
int	wcscmp(const wchar_t *, const wchar_t *) __pure;
int	wcscoll(const wchar_t *, const wchar_t *);
wchar_t	*wcscpy(wchar_t * __restrict, const wchar_t * __restrict);
size_t	wcscspn(const wchar_t *, const wchar_t *) __pure;
size_t	wcsftime(wchar_t * __restrict, size_t, const wchar_t * __restrict,
	    const struct tm * __restrict);
size_t	wcslen(const wchar_t *) __pure;
wchar_t	*wcsncat(wchar_t * __restrict, const wchar_t * __restrict,
	    size_t);
int	wcsncmp(const wchar_t *, const wchar_t *, size_t) __pure;
wchar_t	*wcsncpy(wchar_t * __restrict , const wchar_t * __restrict, size_t);
wchar_t	*wcspbrk(const wchar_t *, const wchar_t *) __pure;
wchar_t	*wcsrchr(const wchar_t *, wchar_t) __pure;
size_t	wcsrtombs(char * __restrict, const wchar_t ** __restrict, size_t,
	    mbstate_t * __restrict);
size_t	wcsspn(const wchar_t *, const wchar_t *) __pure;
wchar_t	*wcsstr(const wchar_t * __restrict, const wchar_t * __restrict)
	    __pure;
size_t	wcsxfrm(wchar_t * __restrict, const wchar_t * __restrict, size_t);
int	wctob(wint_t);
double	wcstod(const wchar_t * __restrict, wchar_t ** __restrict);
wchar_t	*wcstok(wchar_t * __restrict, const wchar_t * __restrict,
	    wchar_t ** __restrict);
long	 wcstol(const wchar_t * __restrict, wchar_t ** __restrict, int);
unsigned long
	 wcstoul(const wchar_t * __restrict, wchar_t ** __restrict, int);
wchar_t	*wmemchr(const wchar_t *, wchar_t, size_t) __pure;
int	wmemcmp(const wchar_t *, const wchar_t *, size_t) __pure;
wchar_t	*wmemcpy(wchar_t * __restrict, const wchar_t * __restrict, size_t);
wchar_t	*wmemmove(wchar_t *, const wchar_t *, size_t);
wchar_t	*wmemset(wchar_t *, wchar_t, size_t);
int	wprintf(const wchar_t * __restrict, ...);
int	wscanf(const wchar_t * __restrict, ...);

#ifndef _STDSTREAM_DECLARED
extern struct __sFILE *__stdinp;
extern struct __sFILE *__stdoutp;
extern struct __sFILE *__stderrp;
#define	_STDSTREAM_DECLARED
#endif

#define	getwc(fp)	fgetwc(fp)
#define	getwchar()	fgetwc(__stdinp)
#define	putwc(wc, fp)	fputwc(wc, fp)
#define	putwchar(wc)	fputwc(wc, __stdoutp)

#if __ISO_C_VISIBLE >= 1999
int	vfwscanf(struct __sFILE * __restrict, const wchar_t * __restrict,
	    __va_list);
int	vswscanf(const wchar_t * __restrict, const wchar_t * __restrict,
	    __va_list);
int	vwscanf(const wchar_t * __restrict, __va_list);
float	wcstof(const wchar_t * __restrict, wchar_t ** __restrict);
long double
	wcstold(const wchar_t * __restrict, wchar_t ** __restrict);
#ifdef __LONG_LONG_SUPPORTED
/* LONGLONG */
long long
	wcstoll(const wchar_t * __restrict, wchar_t ** __restrict, int);
/* LONGLONG */
unsigned long long
	 wcstoull(const wchar_t * __restrict, wchar_t ** __restrict, int);
#endif
#endif	/* __ISO_C_VISIBLE >= 1999 */

#if __XSI_VISIBLE
int	wcswidth(const wchar_t *, size_t);
int	wcwidth(wchar_t);
#define	wcwidth(_c)	__wcwidth(_c)
#endif

#if __POSIX_VISIBLE >= 200809 || __BSD_VISIBLE
size_t	mbsnrtowcs(wchar_t * __restrict, const char ** __restrict, size_t,
	    size_t, mbstate_t * __restrict);
wchar_t	*wcpcpy(wchar_t * __restrict, const wchar_t * __restrict);
wchar_t	*wcpncpy(wchar_t * __restrict, const wchar_t * __restrict, size_t);
wchar_t	*wcsdup(const wchar_t *) __malloc_like;
int	wcscasecmp(const wchar_t *, const wchar_t *);
int	wcsncasecmp(const wchar_t *, const wchar_t *, size_t n);
size_t	wcsnlen(const wchar_t *, size_t) __pure;
size_t	wcsnrtombs(char * __restrict, const wchar_t ** __restrict, size_t,
	    size_t, mbstate_t * __restrict);
#endif

#if __BSD_VISIBLE
wchar_t	*fgetwln(struct __sFILE * __restrict, size_t * __restrict);
size_t	wcslcat(wchar_t *, const wchar_t *, size_t);
size_t	wcslcpy(wchar_t *, const wchar_t *, size_t);
#endif
__END_DECLS

#endif /* !_WCHAR_H_ */
