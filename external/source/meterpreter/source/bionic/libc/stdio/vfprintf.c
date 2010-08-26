/*	$OpenBSD: vfprintf.c,v 1.37 2006/01/13 17:56:18 millert Exp $	*/
/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
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

/*
 * Actual printf innards.
 *
 * This code is large and complicated...
 */

#include <sys/types.h>
#include <sys/mman.h>

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "local.h"
#include "fvwrite.h"

static void __find_arguments(const char *fmt0, va_list ap, va_list **argtable,
    size_t *argtablesiz);
static int __grow_type_table(unsigned char **typetable, int *tablesize);

/*
 * Flush out all the vectors defined by the given uio,
 * then reset it so that it can be reused.
 */
static int
__sprint(FILE *fp, struct __suio *uio)
{
	int err;

	if (uio->uio_resid == 0) {
		uio->uio_iovcnt = 0;
		return (0);
	}
	err = __sfvwrite(fp, uio);
	uio->uio_resid = 0;
	uio->uio_iovcnt = 0;
	return (err);
}

/*
 * Helper function for `fprintf to unbuffered unix file': creates a
 * temporary buffer.  We only work on write-only files; this avoids
 * worries about ungetc buffers and so forth.
 */
static int
__sbprintf(FILE *fp, const char *fmt, va_list ap)
{
	int ret;
	FILE fake;
	struct __sfileext fakeext;
	unsigned char buf[BUFSIZ];

	_FILEEXT_SETUP(&fake, &fakeext);
	/* copy the important variables */
	fake._flags = fp->_flags & ~__SNBF;
	fake._file = fp->_file;
	fake._cookie = fp->_cookie;
	fake._write = fp->_write;

	/* set up the buffer */
	fake._bf._base = fake._p = buf;
	fake._bf._size = fake._w = sizeof(buf);
	fake._lbfsize = 0;	/* not actually used, but Just In Case */

	/* do the work, then copy any error status */
	ret = vfprintf(&fake, fmt, ap);
	if (ret >= 0 && fflush(&fake))
		ret = EOF;
	if (fake._flags & __SERR)
		fp->_flags |= __SERR;
	return (ret);
}


#ifdef FLOATING_POINT
#include <locale.h>
#include <math.h>
#include "floatio.h"

#define	BUF		(MAXEXP+MAXFRACT+1)	/* + decimal point */
#define	DEFPREC		6

static char *cvt(double, int, int, char *, int *, int, int *);
static int exponent(char *, int, int);
#else /* no FLOATING_POINT */
#define	BUF		40
#endif /* FLOATING_POINT */

#define STATIC_ARG_TBL_SIZE 8	/* Size of static argument table. */

/* BIONIC: do not link libm for only two rather simple functions */
#ifdef FLOATING_POINT
static  int  _my_isinf(double);
static  int  _my_isnan(double);
#endif

/*
 * Macros for converting digits to letters and vice versa
 */
#define	to_digit(c)	((c) - '0')
#define is_digit(c)	((unsigned)to_digit(c) <= 9)
#define	to_char(n)	((n) + '0')

/*
 * Flags used during conversion.
 */
#define	ALT		0x0001		/* alternate form */
#define	HEXPREFIX	0x0002		/* add 0x or 0X prefix */
#define	LADJUST		0x0004		/* left adjustment */
#define	LONGDBL		0x0008		/* long double; unimplemented */
#define	LONGINT		0x0010		/* long integer */
#define	LLONGINT	0x0020		/* long long integer */
#define	SHORTINT	0x0040		/* short integer */
#define	ZEROPAD		0x0080		/* zero (as opposed to blank) pad */
#define FPT		0x0100		/* Floating point number */
#define PTRINT		0x0200		/* (unsigned) ptrdiff_t */
#define SIZEINT		0x0400		/* (signed) size_t */
#define CHARINT		0x0800		/* 8 bit integer */
#define MAXINT		0x1000		/* largest integer size (intmax_t) */

int
vfprintf(FILE *fp, const char *fmt0, __va_list ap)
{
	char *fmt;	/* format string */
	int ch;	/* character from fmt */
	int n, m, n2;	/* handy integers (short term usage) */
	char *cp;	/* handy char pointer (short term usage) */
	char *cp_free = NULL;  /* BIONIC: copy of cp to be freed after usage */
	struct __siov *iovp;/* for PRINT macro */
	int flags;	/* flags as above */
	int ret;		/* return value accumulator */
	int width;		/* width from format (%8d), or 0 */
	int prec;		/* precision from format (%.3d), or -1 */
	char sign;		/* sign prefix (' ', '+', '-', or \0) */
	wchar_t wc;
	void* ps;
#ifdef FLOATING_POINT
	char *decimal_point = ".";
	char softsign;		/* temporary negative sign for floats */
	double _double = 0.;	/* double precision arguments %[eEfgG] */
	int expt;		/* integer value of exponent */
	int expsize = 0;	/* character count for expstr */
	int ndig;		/* actual number of digits returned by cvt */
	char expstr[7];		/* buffer for exponent string */
#endif

	uintmax_t _umax;	/* integer arguments %[diouxX] */
	enum { OCT, DEC, HEX } base;/* base for [diouxX] conversion */
	int dprec;		/* a copy of prec if [diouxX], 0 otherwise */
	int realsz;		/* field size expanded by dprec */
	int size;		/* size of converted field or string */
	char* xdigs = NULL;		/* digits for [xX] conversion */
#define NIOV 8
	struct __suio uio;	/* output information: summary */
	struct __siov iov[NIOV];/* ... and individual io vectors */
	char buf[BUF];		/* space for %c, %[diouxX], %[eEfgG] */
	char ox[2];		/* space for 0x hex-prefix */
	va_list *argtable;	/* args, built due to positional arg */
	va_list statargtable[STATIC_ARG_TBL_SIZE];
	size_t argtablesiz;
	int nextarg;		/* 1-based argument index */
	va_list orgap;		/* original argument pointer */
	/*
	 * Choose PADSIZE to trade efficiency vs. size.  If larger printf
	 * fields occur frequently, increase PADSIZE and make the initialisers
	 * below longer.
	 */
#define	PADSIZE	16		/* pad chunk size */
	static char blanks[PADSIZE] =
	 {' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' '};
	static char zeroes[PADSIZE] =
	 {'0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0'};

	/*
	 * BEWARE, these `goto error' on error, and PAD uses `n'.
	 */
#define	PRINT(ptr, len) do { \
	iovp->iov_base = (ptr); \
	iovp->iov_len = (len); \
	uio.uio_resid += (len); \
	iovp++; \
	if (++uio.uio_iovcnt >= NIOV) { \
		if (__sprint(fp, &uio)) \
			goto error; \
		iovp = iov; \
	} \
} while (0)
#define	PAD(howmany, with) do { \
	if ((n = (howmany)) > 0) { \
		while (n > PADSIZE) { \
			PRINT(with, PADSIZE); \
			n -= PADSIZE; \
		} \
		PRINT(with, n); \
	} \
} while (0)
#define	FLUSH() do { \
	if (uio.uio_resid && __sprint(fp, &uio)) \
		goto error; \
	uio.uio_iovcnt = 0; \
	iovp = iov; \
} while (0)

	/*
	 * To extend shorts properly, we need both signed and unsigned
	 * argument extraction methods.
	 */
#define	SARG() \
	((intmax_t)(flags&MAXINT ? GETARG(intmax_t) : \
	    flags&LLONGINT ? GETARG(long long) : \
	    flags&LONGINT ? GETARG(long) : \
	    flags&PTRINT ? GETARG(ptrdiff_t) : \
	    flags&SIZEINT ? GETARG(ssize_t) : \
	    flags&SHORTINT ? (short)GETARG(int) : \
	    flags&CHARINT ? (__signed char)GETARG(int) : \
	    GETARG(int)))
#define	UARG() \
	((uintmax_t)(flags&MAXINT ? GETARG(uintmax_t) : \
	    flags&LLONGINT ? GETARG(unsigned long long) : \
	    flags&LONGINT ? GETARG(unsigned long) : \
	    flags&PTRINT ? (uintptr_t)GETARG(ptrdiff_t) : /* XXX */ \
	    flags&SIZEINT ? GETARG(size_t) : \
	    flags&SHORTINT ? (unsigned short)GETARG(int) : \
	    flags&CHARINT ? (unsigned char)GETARG(int) : \
	    GETARG(unsigned int)))

	 /*
	  * Get * arguments, including the form *nn$.  Preserve the nextarg
	  * that the argument can be gotten once the type is determined.
	  */
#define GETASTER(val) \
	n2 = 0; \
	cp = fmt; \
	while (is_digit(*cp)) { \
		n2 = 10 * n2 + to_digit(*cp); \
		cp++; \
	} \
	if (*cp == '$') { \
		int hold = nextarg; \
		if (argtable == NULL) { \
			argtable = statargtable; \
			__find_arguments(fmt0, orgap, &argtable, &argtablesiz); \
		} \
		nextarg = n2; \
		val = GETARG(int); \
		nextarg = hold; \
		fmt = ++cp; \
	} else { \
		val = GETARG(int); \
	}

/*
* Get the argument indexed by nextarg.   If the argument table is
* built, use it to get the argument.  If its not, get the next
* argument (and arguments must be gotten sequentially).
*/
#define GETARG(type) \
	(((argtable != NULL) ? (void)(ap = argtable[nextarg]) : (void)0), \
	 nextarg++, va_arg(ap, type))

	_SET_ORIENTATION(fp, -1);
	/* sorry, fprintf(read_only_file, "") returns EOF, not 0 */
	if (cantwrite(fp)) {
		errno = EBADF;
		return (EOF);
	}

	/* optimise fprintf(stderr) (and other unbuffered Unix files) */
	if ((fp->_flags & (__SNBF|__SWR|__SRW)) == (__SNBF|__SWR) &&
	    fp->_file >= 0)
		return (__sbprintf(fp, fmt0, ap));

	fmt = (char *)fmt0;
	argtable = NULL;
	nextarg = 1;
	va_copy(orgap, ap);
	uio.uio_iov = iovp = iov;
	uio.uio_resid = 0;
	uio.uio_iovcnt = 0;
	ret = 0;

	memset(&ps, 0, sizeof(ps));
	/*
	 * Scan the format for conversions (`%' character).
	 */
	for (;;) {
		cp = fmt;
#if 1  /* BIONIC */
                n = -1;
                while ( (wc = *fmt) != 0 ) {
                    if (wc == '%') {
                        n = 1;
                        break;
                    }
                    fmt++;
                }
#else
		while ((n = mbrtowc(&wc, fmt, MB_CUR_MAX, &ps)) > 0) {
			fmt += n;
			if (wc == '%') {
				fmt--;
				break;
			}
		}
#endif
		if ((m = fmt - cp) != 0) {
			PRINT(cp, m);
			ret += m;
		}
		if (n <= 0)
			goto done;
		fmt++;		/* skip over '%' */

		flags = 0;
		dprec = 0;
		width = 0;
		prec = -1;
		sign = '\0';

rflag:		ch = *fmt++;
reswitch:	switch (ch) {
		case ' ':
			/*
			 * ``If the space and + flags both appear, the space
			 * flag will be ignored.''
			 *	-- ANSI X3J11
			 */
			if (!sign)
				sign = ' ';
			goto rflag;
		case '#':
			flags |= ALT;
			goto rflag;
		case '*':
			/*
			 * ``A negative field width argument is taken as a
			 * - flag followed by a positive field width.''
			 *	-- ANSI X3J11
			 * They don't exclude field widths read from args.
			 */
			GETASTER(width);
			if (width >= 0)
				goto rflag;
			width = -width;
			/* FALLTHROUGH */
		case '-':
			flags |= LADJUST;
			goto rflag;
		case '+':
			sign = '+';
			goto rflag;
		case '.':
			if ((ch = *fmt++) == '*') {
				GETASTER(n);
				prec = n < 0 ? -1 : n;
				goto rflag;
			}
			n = 0;
			while (is_digit(ch)) {
				n = 10 * n + to_digit(ch);
				ch = *fmt++;
			}
			if (ch == '$') {
				nextarg = n;
				if (argtable == NULL) {
					argtable = statargtable;
					__find_arguments(fmt0, orgap,
					    &argtable, &argtablesiz);
				}
				goto rflag;
			}
			prec = n < 0 ? -1 : n;
			goto reswitch;
		case '0':
			/*
			 * ``Note that 0 is taken as a flag, not as the
			 * beginning of a field width.''
			 *	-- ANSI X3J11
			 */
			flags |= ZEROPAD;
			goto rflag;
		case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			n = 0;
			do {
				n = 10 * n + to_digit(ch);
				ch = *fmt++;
			} while (is_digit(ch));
			if (ch == '$') {
				nextarg = n;
				if (argtable == NULL) {
					argtable = statargtable;
					__find_arguments(fmt0, orgap,
					    &argtable, &argtablesiz);
				}
				goto rflag;
			}
			width = n;
			goto reswitch;
#ifdef FLOATING_POINT
		case 'L':
			flags |= LONGDBL;
			goto rflag;
#endif
		case 'h':
			flags |= SHORTINT;
			goto rflag;
		case 'j':
			flags |= MAXINT;
			goto rflag;
		case 'l':
			if (*fmt == 'l') {
				fmt++;
				flags |= LLONGINT;
			} else {
				flags |= LONGINT;
			}
			goto rflag;
		case 'q':
			flags |= LLONGINT;
			goto rflag;
		case 't':
			flags |= PTRINT;
			goto rflag;
		case 'z':
			flags |= SIZEINT;
			goto rflag;
		case 'c':
			*(cp = buf) = GETARG(int);
			size = 1;
			sign = '\0';
			break;
		case 'D':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'd':
		case 'i':
			_umax = SARG();
			if ((intmax_t)_umax < 0) {
				_umax = -_umax;
				sign = '-';
			}
			base = DEC;
			goto number;
#ifdef FLOATING_POINT
		case 'e':
		case 'E':
		case 'f':
		case 'g':
		case 'G':
			if (prec == -1) {
				prec = DEFPREC;
			} else if ((ch == 'g' || ch == 'G') && prec == 0) {
				prec = 1;
			}

			if (flags & LONGDBL) {
				_double = (double) GETARG(long double);
			} else {
				_double = GETARG(double);
			}

			/* do this before tricky precision changes */
			if (_my_isinf(_double)) {
				if (_double < 0)
					sign = '-';
				cp = "Inf";
				size = 3;
				break;
			}
			if (_my_isnan(_double)) {
				cp = "NaN";
				size = 3;
				break;
			}

			flags |= FPT;
			cp = cvt(_double, prec, flags, &softsign,
				&expt, ch, &ndig);
		    cp_free = cp;
			if (ch == 'g' || ch == 'G') {
				if (expt <= -4 || expt > prec)
					ch = (ch == 'g') ? 'e' : 'E';
				else
					ch = 'g';
			}
			if (ch <= 'e') {	/* 'e' or 'E' fmt */
				--expt;
				expsize = exponent(expstr, expt, ch);
				size = expsize + ndig;
				if (ndig > 1 || flags & ALT)
					++size;
			} else if (ch == 'f') {		/* f fmt */
				if (expt > 0) {
					size = expt;
					if (prec || flags & ALT)
						size += prec + 1;
				} else	/* "0.X" */
					size = prec + 2;
			} else if (expt >= ndig) {	/* fixed g fmt */
				size = expt;
				if (flags & ALT)
					++size;
			} else
				size = ndig + (expt > 0 ?
					1 : 2 - expt);

			if (softsign)
				sign = '-';
			break;
#endif /* FLOATING_POINT */
/* the Android security team suggests removing support for %n
 * since it has no real practical value, and could lead to
 * running malicious code (for really bugy programs that
 * send to printf() user-generated formatting strings).
 */
#if 0
		case 'n':
			if (flags & LLONGINT)
				*GETARG(long long *) = ret;
			else if (flags & LONGINT)
				*GETARG(long *) = ret;
			else if (flags & SHORTINT)
				*GETARG(short *) = ret;
			else if (flags & CHARINT)
				*GETARG(__signed char *) = ret;
			else if (flags & PTRINT)
				*GETARG(ptrdiff_t *) = ret;
			else if (flags & SIZEINT)
				*GETARG(ssize_t *) = ret;
			else if (flags & MAXINT)
				*GETARG(intmax_t *) = ret;
			else
				*GETARG(int *) = ret;
			continue;	/* no output */
#endif
		case 'O':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'o':
			_umax = UARG();
			base = OCT;
			goto nosign;
		case 'p':
			/*
			 * ``The argument shall be a pointer to void.  The
			 * value of the pointer is converted to a sequence
			 * of printable characters, in an implementation-
			 * defined manner.''
			 *	-- ANSI X3J11
			 */
			/* NOSTRICT */
			_umax = (u_long)GETARG(void *);
			base = HEX;
			xdigs = "0123456789abcdef";
			flags |= HEXPREFIX;
			ch = 'x';
			goto nosign;
		case 's':
			if ((cp = GETARG(char *)) == NULL)
				cp = "(null)";
			if (prec >= 0) {
				/*
				 * can't use strlen; can only look for the
				 * NUL in the first `prec' characters, and
				 * strlen() will go further.
				 */
				char *p = memchr(cp, 0, prec);

				if (p != NULL) {
					size = p - cp;
					if (size > prec)
						size = prec;
				} else
					size = prec;
			} else
				size = strlen(cp);
			sign = '\0';
			break;
		case 'U':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'u':
			_umax = UARG();
			base = DEC;
			goto nosign;
		case 'X':
			xdigs = "0123456789ABCDEF";
			goto hex;
		case 'x':
			xdigs = "0123456789abcdef";
hex:			_umax = UARG();
			base = HEX;
			/* leading 0x/X only if non-zero */
			if (flags & ALT && _umax != 0)
				flags |= HEXPREFIX;

			/* unsigned conversions */
nosign:			sign = '\0';
			/*
			 * ``... diouXx conversions ... if a precision is
			 * specified, the 0 flag will be ignored.''
			 *	-- ANSI X3J11
			 */
number:			if ((dprec = prec) >= 0)
				flags &= ~ZEROPAD;

			/*
			 * ``The result of converting a zero value with an
			 * explicit precision of zero is no characters.''
			 *	-- ANSI X3J11
			 */
			cp = buf + BUF;
			if (_umax != 0 || prec != 0) {
				/*
				 * Unsigned mod is hard, and unsigned mod
				 * by a constant is easier than that by
				 * a variable; hence this switch.
				 */
				switch (base) {
				case OCT:
					do {
						*--cp = to_char(_umax & 7);
						_umax >>= 3;
					} while (_umax);
					/* handle octal leading 0 */
					if (flags & ALT && *cp != '0')
						*--cp = '0';
					break;

				case DEC:
					/* many numbers are 1 digit */
					while (_umax >= 10) {
						*--cp = to_char(_umax % 10);
						_umax /= 10;
					}
					*--cp = to_char(_umax);
					break;

				case HEX:
					do {
						*--cp = xdigs[_umax & 15];
						_umax >>= 4;
					} while (_umax);
					break;

				default:
					cp = "bug in vfprintf: bad base";
					size = strlen(cp);
					goto skipsize;
				}
			}
			size = buf + BUF - cp;
		skipsize:
			break;
		default:	/* "%?" prints ?, unless ? is NUL */
			if (ch == '\0')
				goto done;
			/* pretend it was %c with argument ch */
			cp = buf;
			*cp = ch;
			size = 1;
			sign = '\0';
			break;
		}

		/*
		 * All reasonable formats wind up here.  At this point, `cp'
		 * points to a string which (if not flags&LADJUST) should be
		 * padded out to `width' places.  If flags&ZEROPAD, it should
		 * first be prefixed by any sign or other prefix; otherwise,
		 * it should be blank padded before the prefix is emitted.
		 * After any left-hand padding and prefixing, emit zeroes
		 * required by a decimal [diouxX] precision, then print the
		 * string proper, then emit zeroes required by any leftover
		 * floating precision; finally, if LADJUST, pad with blanks.
		 *
		 * Compute actual size, so we know how much to pad.
		 * size excludes decimal prec; realsz includes it.
		 */
		realsz = dprec > size ? dprec : size;
		if (sign)
			realsz++;
		else if (flags & HEXPREFIX)
			realsz+= 2;

		/* right-adjusting blank padding */
		if ((flags & (LADJUST|ZEROPAD)) == 0)
			PAD(width - realsz, blanks);

		/* prefix */
		if (sign) {
			PRINT(&sign, 1);
		} else if (flags & HEXPREFIX) {
			ox[0] = '0';
			ox[1] = ch;
			PRINT(ox, 2);
		}

		/* right-adjusting zero padding */
		if ((flags & (LADJUST|ZEROPAD)) == ZEROPAD)
			PAD(width - realsz, zeroes);

		/* leading zeroes from decimal precision */
		PAD(dprec - size, zeroes);

		/* the string or number proper */
#ifdef FLOATING_POINT
		if ((flags & FPT) == 0) {
			PRINT(cp, size);
		} else {	/* glue together f_p fragments */
			if (ch >= 'f') {	/* 'f' or 'g' */
				if (_double == 0) {
					/* kludge for __dtoa irregularity */
					PRINT("0", 1);
					if (expt < ndig || (flags & ALT) != 0) {
						PRINT(decimal_point, 1);
						PAD(ndig - 1, zeroes);
					}
				} else if (expt <= 0) {
					PRINT("0", 1);
					PRINT(decimal_point, 1);
					PAD(-expt, zeroes);
					PRINT(cp, ndig);
				} else if (expt >= ndig) {
					PRINT(cp, ndig);
					PAD(expt - ndig, zeroes);
					if (flags & ALT)
						PRINT(".", 1);
				} else {
					PRINT(cp, expt);
					cp += expt;
					PRINT(".", 1);
					PRINT(cp, ndig-expt);
				}
			} else {	/* 'e' or 'E' */
				if (ndig > 1 || flags & ALT) {
					ox[0] = *cp++;
					ox[1] = '.';
					PRINT(ox, 2);
					if (_double) {
						PRINT(cp, ndig-1);
					} else	/* 0.[0..] */
						/* __dtoa irregularity */
						PAD(ndig - 1, zeroes);
				} else	/* XeYYY */
					PRINT(cp, 1);
				PRINT(expstr, expsize);
			}
		}
#else
		PRINT(cp, size);
#endif
		/* left-adjusting padding (always blank) */
		if (flags & LADJUST)
			PAD(width - realsz, blanks);

		/* finally, adjust ret */
		ret += width > realsz ? width : realsz;

		FLUSH();	/* copy out the I/O vectors */
#if 1   /* BIONIC: remove memory leak when printing doubles */
		if (cp_free) {
		  free(cp_free);
		  cp_free = NULL;
		}
#endif
	}
done:
	FLUSH();
error:
#if 1   /* BIONIC: remove memory leak when printing doubles */
    if (cp_free) {
        free(cp_free);
        cp_free = NULL;
    }
#endif
	if (argtable != NULL && argtable != statargtable) {
		munmap(argtable, argtablesiz);
		argtable = NULL;
	}
	return (__sferror(fp) ? EOF : ret);
	/* NOTREACHED */
}

/*
 * Type ids for argument type table.
 */
#define T_UNUSED	0
#define T_SHORT		1
#define T_U_SHORT	2
#define TP_SHORT	3
#define T_INT		4
#define T_U_INT		5
#define TP_INT		6
#define T_LONG		7
#define T_U_LONG	8
#define TP_LONG		9
#define T_LLONG		10
#define T_U_LLONG	11
#define TP_LLONG	12
#define T_DOUBLE	13
#define T_LONG_DOUBLE	14
#define TP_CHAR		15
#define TP_VOID		16
#define T_PTRINT	17
#define TP_PTRINT	18
#define T_SIZEINT	19
#define T_SSIZEINT	20
#define TP_SSIZEINT	21
#define T_MAXINT	22
#define T_MAXUINT	23
#define TP_MAXINT	24

/*
 * Find all arguments when a positional parameter is encountered.  Returns a
 * table, indexed by argument number, of pointers to each arguments.  The
 * initial argument table should be an array of STATIC_ARG_TBL_SIZE entries.
 * It will be replaced with a mmap-ed one if it overflows (malloc cannot be
 * used since we are attempting to make snprintf thread safe, and alloca is
 * problematic since we have nested functions..)
 */
static void
__find_arguments(const char *fmt0, va_list ap, va_list **argtable,
    size_t *argtablesiz)
{
	char *fmt;	/* format string */
	int ch;	/* character from fmt */
	int n, n2;	/* handy integer (short term usage) */
	char *cp;	/* handy char pointer (short term usage) */
	int flags;	/* flags as above */
	unsigned char *typetable; /* table of types */
	unsigned char stattypetable[STATIC_ARG_TBL_SIZE];
	int tablesize;		/* current size of type table */
	int tablemax;		/* largest used index in table */
	int nextarg;		/* 1-based argument index */
	wchar_t wc;
	void* ps;

	/*
	 * Add an argument type to the table, expanding if necessary.
	 */
#define ADDTYPE(type) \
	((nextarg >= tablesize) ? \
		__grow_type_table(&typetable, &tablesize) : 0, \
	(nextarg > tablemax) ? tablemax = nextarg : 0, \
	typetable[nextarg++] = type)

#define	ADDSARG() \
        ((flags&MAXINT) ? ADDTYPE(T_MAXINT) : \
	    ((flags&PTRINT) ? ADDTYPE(T_PTRINT) : \
	    ((flags&SIZEINT) ? ADDTYPE(T_SSIZEINT) : \
	    ((flags&LLONGINT) ? ADDTYPE(T_LLONG) : \
	    ((flags&LONGINT) ? ADDTYPE(T_LONG) : \
	    ((flags&SHORTINT) ? ADDTYPE(T_SHORT) : ADDTYPE(T_INT)))))))

#define	ADDUARG() \
        ((flags&MAXINT) ? ADDTYPE(T_MAXUINT) : \
	    ((flags&PTRINT) ? ADDTYPE(T_PTRINT) : \
	    ((flags&SIZEINT) ? ADDTYPE(T_SIZEINT) : \
	    ((flags&LLONGINT) ? ADDTYPE(T_U_LLONG) : \
	    ((flags&LONGINT) ? ADDTYPE(T_U_LONG) : \
	    ((flags&SHORTINT) ? ADDTYPE(T_U_SHORT) : ADDTYPE(T_U_INT)))))))

	/*
	 * Add * arguments to the type array.
	 */
#define ADDASTER() \
	n2 = 0; \
	cp = fmt; \
	while (is_digit(*cp)) { \
		n2 = 10 * n2 + to_digit(*cp); \
		cp++; \
	} \
	if (*cp == '$') { \
		int hold = nextarg; \
		nextarg = n2; \
		ADDTYPE(T_INT); \
		nextarg = hold; \
		fmt = ++cp; \
	} else { \
		ADDTYPE(T_INT); \
	}
	fmt = (char *)fmt0;
	typetable = stattypetable;
	tablesize = STATIC_ARG_TBL_SIZE;
	tablemax = 0;
	nextarg = 1;
	memset(typetable, T_UNUSED, STATIC_ARG_TBL_SIZE);
	memset(&ps, 0, sizeof(ps));

	/*
	 * Scan the format for conversions (`%' character).
	 */
	for (;;) {
		cp = fmt;
#if 1  /* BIONIC */
                n = -1;
                while ((wc = *fmt) != 0) {
                    if (wc == '%') {
                        n = 1;
                        break;
                    }
                    fmt++;
                }
#else
		while ((n = mbrtowc(&wc, fmt, MB_CUR_MAX, &ps)) > 0) {
			fmt += n;
			if (wc == '%') {
				fmt--;
				break;
			}
		}
#endif
		if (n <= 0)
			goto done;
		fmt++;		/* skip over '%' */

		flags = 0;

rflag:		ch = *fmt++;
reswitch:	switch (ch) {
		case ' ':
		case '#':
			goto rflag;
		case '*':
			ADDASTER();
			goto rflag;
		case '-':
		case '+':
			goto rflag;
		case '.':
			if ((ch = *fmt++) == '*') {
				ADDASTER();
				goto rflag;
			}
			while (is_digit(ch)) {
				ch = *fmt++;
			}
			goto reswitch;
		case '0':
			goto rflag;
		case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			n = 0;
			do {
				n = 10 * n + to_digit(ch);
				ch = *fmt++;
			} while (is_digit(ch));
			if (ch == '$') {
				nextarg = n;
				goto rflag;
			}
			goto reswitch;
#ifdef FLOATING_POINT
		case 'L':
			flags |= LONGDBL;
			goto rflag;
#endif
		case 'h':
			if (*fmt == 'h') {
				fmt++;
				flags |= CHARINT;
			} else {
				flags |= SHORTINT;
			}
			goto rflag;
		case 'l':
			if (*fmt == 'l') {
				fmt++;
				flags |= LLONGINT;
			} else {
				flags |= LONGINT;
			}
			goto rflag;
		case 'q':
			flags |= LLONGINT;
			goto rflag;
		case 't':
			flags |= PTRINT;
			goto rflag;
		case 'z':
			flags |= SIZEINT;
			goto rflag;
		case 'c':
			ADDTYPE(T_INT);
			break;
		case 'D':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'd':
		case 'i':
			ADDSARG();
			break;
#ifdef FLOATING_POINT
		case 'e':
		case 'E':
		case 'f':
		case 'g':
		case 'G':
			if (flags & LONGDBL)
				ADDTYPE(T_LONG_DOUBLE);
			else
				ADDTYPE(T_DOUBLE);
			break;
#endif /* FLOATING_POINT */
		case 'n':
			if (flags & LLONGINT)
				ADDTYPE(TP_LLONG);
			else if (flags & LONGINT)
				ADDTYPE(TP_LONG);
			else if (flags & SHORTINT)
				ADDTYPE(TP_SHORT);
			else if (flags & PTRINT)
				ADDTYPE(TP_PTRINT);
			else if (flags & SIZEINT)
				ADDTYPE(TP_SSIZEINT);
			else if (flags & MAXINT)
				ADDTYPE(TP_MAXINT);
			else
				ADDTYPE(TP_INT);
			continue;	/* no output */
		case 'O':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'o':
			ADDUARG();
			break;
		case 'p':
			ADDTYPE(TP_VOID);
			break;
		case 's':
			ADDTYPE(TP_CHAR);
			break;
		case 'U':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'u':
		case 'X':
		case 'x':
			ADDUARG();
			break;
		default:	/* "%?" prints ?, unless ? is NUL */
			if (ch == '\0')
				goto done;
			break;
		}
	}
done:
	/*
	 * Build the argument table.
	 */
	if (tablemax >= STATIC_ARG_TBL_SIZE) {
		*argtablesiz = sizeof (va_list) * (tablemax + 1);
		*argtable = (va_list *)mmap(NULL, *argtablesiz,
		    PROT_WRITE|PROT_READ, MAP_ANON|MAP_PRIVATE, -1, 0);
	}

#if 0
	/* XXX is this required? */
	(*argtable) [0] = NULL;
#endif
	for (n = 1; n <= tablemax; n++) {
		va_copy((*argtable)[n], ap);
		switch (typetable[n]) {
		case T_UNUSED:
			(void) va_arg(ap, int);
			break;
		case T_SHORT:
			(void) va_arg(ap, int);
			break;
		case T_U_SHORT:
			(void) va_arg(ap, int);
			break;
		case TP_SHORT:
			(void) va_arg(ap, short *);
			break;
		case T_INT:
			(void) va_arg(ap, int);
			break;
		case T_U_INT:
			(void) va_arg(ap, unsigned int);
			break;
		case TP_INT:
			(void) va_arg(ap, int *);
			break;
		case T_LONG:
			(void) va_arg(ap, long);
			break;
		case T_U_LONG:
			(void) va_arg(ap, unsigned long);
			break;
		case TP_LONG:
			(void) va_arg(ap, long *);
			break;
		case T_LLONG:
			(void) va_arg(ap, long long);
			break;
		case T_U_LLONG:
			(void) va_arg(ap, unsigned long long);
			break;
		case TP_LLONG:
			(void) va_arg(ap, long long *);
			break;
		case T_DOUBLE:
			(void) va_arg(ap, double);
			break;
		case T_LONG_DOUBLE:
			(void) va_arg(ap, long double);
			break;
		case TP_CHAR:
			(void) va_arg(ap, char *);
			break;
		case TP_VOID:
			(void) va_arg(ap, void *);
			break;
		case T_PTRINT:
			(void) va_arg(ap, ptrdiff_t);
			break;
		case TP_PTRINT:
			(void) va_arg(ap, ptrdiff_t *);
			break;
		case T_SIZEINT:
			(void) va_arg(ap, size_t);
			break;
		case T_SSIZEINT:
			(void) va_arg(ap, ssize_t);
			break;
		case TP_SSIZEINT:
			(void) va_arg(ap, ssize_t *);
			break;
		case TP_MAXINT:
			(void) va_arg(ap, intmax_t *);
			break;
		}
	}

	if (typetable != NULL && typetable != stattypetable) {
		munmap(typetable, *argtablesiz);
		typetable = NULL;
	}
}

/*
 * Increase the size of the type table.
 */
static int
__grow_type_table(unsigned char **typetable, int *tablesize)
{
	unsigned char *oldtable = *typetable;
	int newsize = *tablesize * 2;

	if (*tablesize == STATIC_ARG_TBL_SIZE) {
		*typetable = (unsigned char *)mmap(NULL,
		    sizeof (unsigned char) * newsize, PROT_WRITE|PROT_READ,
		    MAP_ANON|MAP_PRIVATE, -1, 0);
		/* XXX unchecked */
		memcpy( *typetable, oldtable, *tablesize);
	} else {
		unsigned char *new = (unsigned char *)mmap(NULL,
		    sizeof (unsigned char) * newsize, PROT_WRITE|PROT_READ,
		    MAP_ANON|MAP_PRIVATE, -1, 0);
		memmove(new, *typetable, *tablesize);
		munmap(*typetable, *tablesize);
		*typetable = new;
		/* XXX unchecked */
	}
	memset(*typetable + *tablesize, T_UNUSED, (newsize - *tablesize));

	*tablesize = newsize;
	return(0);
}


#ifdef FLOATING_POINT

extern char *__dtoa(double, int, int, int *, int *, char **);

static char *
cvt(double value, int ndigits, int flags, char *sign, int *decpt, int ch,
    int *length)
{
	int mode, dsgn;
	char *digits, *bp, *rve;
	static  char  temp[64];

	if (ch == 'f') {
		mode = 3;		/* ndigits after the decimal point */
	} else {
		/* To obtain ndigits after the decimal point for the 'e'
		 * and 'E' formats, round to ndigits + 1 significant
		 * figures.
		 */
		if (ch == 'e' || ch == 'E') {
			ndigits++;
		}
		mode = 2;		/* ndigits significant digits */
	}

	if (value < 0) {
		value = -value;
		*sign = '-';
	} else
		*sign = '\000';
	digits = __dtoa(value, mode, ndigits, decpt, &dsgn, &rve);
	if ((ch != 'g' && ch != 'G') || flags & ALT) {	/* Print trailing zeros */
		bp = digits + ndigits;
		if (ch == 'f') {
			if (*digits == '0' && value)
				*decpt = -ndigits + 1;
			bp += *decpt;
		}
		if (value == 0)	/* kludge for __dtoa irregularity */
			rve = bp;
		while (rve < bp)
			*rve++ = '0';
	}
	*length = rve - digits;
	return (digits);
}

static int
exponent(char *p0, int exp, int fmtch)
{
	char *p, *t;
	char expbuf[MAXEXP];

	p = p0;
	*p++ = fmtch;
	if (exp < 0) {
		exp = -exp;
		*p++ = '-';
	}
	else
		*p++ = '+';
	t = expbuf + MAXEXP;
	if (exp > 9) {
		do {
			*--t = to_char(exp % 10);
		} while ((exp /= 10) > 9);
		*--t = to_char(exp);
		for (; t < expbuf + MAXEXP; *p++ = *t++);
	}
	else {
		*p++ = '0';
		*p++ = to_char(exp);
	}
	return (p - p0);
}


/* BIONIC */
#include <machine/ieee.h>
typedef union {
    double              d;
    struct ieee_double  i;
} ieee_u;

static int
_my_isinf (double  value)
{
    ieee_u   u;

    u.d = value;
    return (u.i.dbl_exp == 2047 && u.i.dbl_frach == 0 && u.i.dbl_fracl == 0);
}

static int
_my_isnan (double  value)
{
    ieee_u   u;

    u.d = value;
    return (u.i.dbl_exp == 2047 && (u.i.dbl_frach != 0 || u.i.dbl_fracl != 0));
}
#endif /* FLOATING_POINT */
