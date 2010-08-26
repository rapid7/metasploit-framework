/*	$OpenBSD: ctype.h,v 1.19 2005/12/13 00:35:22 millert Exp $	*/
/*	$NetBSD: ctype.h,v 1.14 1994/10/26 00:55:47 cgd Exp $	*/

/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)ctype.h	5.3 (Berkeley) 4/3/91
 */

#ifndef _CTYPE_H_
#define _CTYPE_H_

#include <sys/cdefs.h>

#define	_U	0x01
#define	_L	0x02
#define	_N	0x04
#define	_S	0x08
#define	_P	0x10
#define	_C	0x20
#define	_X	0x40
#define	_B	0x80

__BEGIN_DECLS

extern const char	*_ctype_;
extern const short	*_tolower_tab_;
extern const short	*_toupper_tab_;

/* extern __inline is a GNU C extension */
#ifdef __GNUC__
#  if defined(__GNUC_STDC_INLINE__)
#define	__CTYPE_INLINE	extern __inline __attribute__((__gnu_inline__))
#  else
#define	__CTYPE_INLINE	extern __inline
#  endif
#else
#define	__CTYPE_INLINE	static __inline
#endif

#if defined(__GNUC__) || defined(_ANSI_LIBRARY) || defined(lint)
int	isalnum(int);
int	isalpha(int);
int	iscntrl(int);
int	isdigit(int);
int	isgraph(int);
int	islower(int);
int	isprint(int);
int	ispunct(int);
int	isspace(int);
int	isupper(int);
int	isxdigit(int);
int	tolower(int);
int	toupper(int);

#if __BSD_VISIBLE || __ISO_C_VISIBLE >= 1999 || __POSIX_VISIBLE > 200112 \
    || __XPG_VISIBLE > 600
int	isblank(int);
#endif

#if __BSD_VISIBLE || __XPG_VISIBLE
int	isascii(int);
int	toascii(int);
int	_tolower(int);
int	_toupper(int);
#endif /* __BSD_VISIBLE || __XPG_VISIBLE */

#endif /* __GNUC__ || _ANSI_LIBRARY || lint */

#if defined(NDEBUG)

__CTYPE_INLINE int isalnum(int c)
{
	return (c == -1 ? 0 : ((_ctype_ + 1)[(unsigned char)c] & (_U|_L|_N)));
}

__CTYPE_INLINE int isalpha(int c)
{
	return (c == -1 ? 0 : ((_ctype_ + 1)[(unsigned char)c] & (_U|_L)));
}

__CTYPE_INLINE int iscntrl(int c)
{
	return (c == -1 ? 0 : ((_ctype_ + 1)[(unsigned char)c] & _C));
}

__CTYPE_INLINE int isdigit(int c)
{
	return (c == -1 ? 0 : ((_ctype_ + 1)[(unsigned char)c] & _N));
}

__CTYPE_INLINE int isgraph(int c)
{
	return (c == -1 ? 0 : ((_ctype_ + 1)[(unsigned char)c] & (_P|_U|_L|_N)));
}

__CTYPE_INLINE int islower(int c)
{
	return (c == -1 ? 0 : ((_ctype_ + 1)[(unsigned char)c] & _L));
}

__CTYPE_INLINE int isprint(int c)
{
	return (c == -1 ? 0 : ((_ctype_ + 1)[(unsigned char)c] & (_P|_U|_L|_N|_B)));
}

__CTYPE_INLINE int ispunct(int c)
{
	return (c == -1 ? 0 : ((_ctype_ + 1)[(unsigned char)c] & _P));
}

__CTYPE_INLINE int isspace(int c)
{
	return (c == -1 ? 0 : ((_ctype_ + 1)[(unsigned char)c] & _S));
}

__CTYPE_INLINE int isupper(int c)
{
	return (c == -1 ? 0 : ((_ctype_ + 1)[(unsigned char)c] & _U));
}

__CTYPE_INLINE int isxdigit(int c)
{
	return (c == -1 ? 0 : ((_ctype_ + 1)[(unsigned char)c] & (_N|_X)));
}

__CTYPE_INLINE int tolower(int c)
{
	if ((unsigned int)c > 255)
		return (c);
	return ((_tolower_tab_ + 1)[c]);
}

__CTYPE_INLINE int toupper(int c)
{
	if ((unsigned int)c > 255)
		return (c);
	return ((_toupper_tab_ + 1)[c]);
}

#if __BSD_VISIBLE || __ISO_C_VISIBLE >= 1999 || __POSIX_VISIBLE > 200112 \
    || __XPG_VISIBLE > 600
__CTYPE_INLINE int isblank(int c)
{
	return (c == ' ' || c == '\t');
}
#endif

#if __BSD_VISIBLE || __XPG_VISIBLE
__CTYPE_INLINE int isascii(int c)
{
	return ((unsigned int)c <= 0177);
}

__CTYPE_INLINE int toascii(int c)
{
	return (c & 0177);
}

__CTYPE_INLINE int _tolower(int c)
{
	return (c - 'A' + 'a');
}

__CTYPE_INLINE int _toupper(int c)
{
	return (c - 'a' + 'A');
}
#endif /* __BSD_VISIBLE || __XPG_VISIBLE */

#endif /* NDEBUG */

__END_DECLS

#undef __CTYPE_INLINE

#endif /* !_CTYPE_H_ */
