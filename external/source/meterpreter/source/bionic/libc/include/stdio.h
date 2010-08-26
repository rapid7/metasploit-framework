/*	$OpenBSD: stdio.h,v 1.35 2006/01/13 18:10:09 miod Exp $	*/
/*	$NetBSD: stdio.h,v 1.18 1996/04/25 18:29:21 jtc Exp $	*/

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
 *
 *	@(#)stdio.h	5.17 (Berkeley) 6/3/91
 */

#ifndef	_STDIO_H_
#define	_STDIO_H_

#include <sys/cdefs.h>
#include <sys/_types.h>

/* va_list and size_t must be defined by stdio.h according to Posix */
#define __need___va_list
#include <stdarg.h>

/* note that this forces stddef.h to *only* define size_t */
#define __need_size_t
#include <stddef.h>

#include <stddef.h>

#if __BSD_VISIBLE || __POSIX_VISIBLE || __XPG_VISIBLE
#include <sys/types.h>	/* XXX should be removed */
#endif

#ifndef	_SIZE_T_DEFINED_
#define	_SIZE_T_DEFINED_
typedef	unsigned long    size_t;
#endif

#ifndef	_OFF_T_DEFINED_
#define	_OFF_T_DEFINED_
typedef	long    off_t;
#endif

#ifndef NULL
#ifdef 	__GNUG__
#define	NULL	__null
#else
#define	NULL	0L
#endif
#endif

#define	_FSTDIO			/* Define for new stdio with functions. */

typedef off_t fpos_t;		/* stdio file position type */

/*
 * NB: to fit things in six character monocase externals, the stdio
 * code uses the prefix `__s' for stdio objects, typically followed
 * by a three-character attempt at a mnemonic.
 */

/* stdio buffers */
struct __sbuf {
	unsigned char *_base;
	int	_size;
};

/*
 * stdio state variables.
 *
 * The following always hold:
 *
 *	if (_flags&(__SLBF|__SWR)) == (__SLBF|__SWR),
 *		_lbfsize is -_bf._size, else _lbfsize is 0
 *	if _flags&__SRD, _w is 0
 *	if _flags&__SWR, _r is 0
 *
 * This ensures that the getc and putc macros (or inline functions) never
 * try to write or read from a file that is in `read' or `write' mode.
 * (Moreover, they can, and do, automatically switch from read mode to
 * write mode, and back, on "r+" and "w+" files.)
 *
 * _lbfsize is used only to make the inline line-buffered output stream
 * code as compact as possible.
 *
 * _ub, _up, and _ur are used when ungetc() pushes back more characters
 * than fit in the current _bf, or when ungetc() pushes back a character
 * that does not match the previous one in _bf.  When this happens,
 * _ub._base becomes non-nil (i.e., a stream has ungetc() data iff
 * _ub._base!=NULL) and _up and _ur save the current values of _p and _r.
 *
 * NOTE: if you change this structure, you also need to update the
 * std() initializer in findfp.c.
 */
typedef	struct __sFILE {
	unsigned char *_p;	/* current position in (some) buffer */
	int	_r;		/* read space left for getc() */
	int	_w;		/* write space left for putc() */
	short	_flags;		/* flags, below; this FILE is free if 0 */
	short	_file;		/* fileno, if Unix descriptor, else -1 */
	struct	__sbuf _bf;	/* the buffer (at least 1 byte, if !NULL) */
	int	_lbfsize;	/* 0 or -_bf._size, for inline putc */

	/* operations */
	void	*_cookie;	/* cookie passed to io functions */
	int	(*_close)(void *);
	int	(*_read)(void *, char *, int);
	fpos_t	(*_seek)(void *, fpos_t, int);
	int	(*_write)(void *, const char *, int);

	/* extension data, to avoid further ABI breakage */
	struct	__sbuf _ext;
	/* data for long sequences of ungetc() */
	unsigned char *_up;	/* saved _p when _p is doing ungetc data */
	int	_ur;		/* saved _r when _r is counting ungetc data */

	/* tricks to meet minimum requirements even when malloc() fails */
	unsigned char _ubuf[3];	/* guarantee an ungetc() buffer */
	unsigned char _nbuf[1];	/* guarantee a getc() buffer */

	/* separate buffer for fgetln() when line crosses buffer boundary */
	struct	__sbuf _lb;	/* buffer for fgetln() */

	/* Unix stdio files get aligned to block boundaries on fseek() */
	int	_blksize;	/* stat.st_blksize (may be != _bf._size) */
	fpos_t	_offset;	/* current lseek offset */
} FILE;

__BEGIN_DECLS
extern FILE __sF[];
__END_DECLS

#define	__SLBF	0x0001		/* line buffered */
#define	__SNBF	0x0002		/* unbuffered */
#define	__SRD	0x0004		/* OK to read */
#define	__SWR	0x0008		/* OK to write */
	/* RD and WR are never simultaneously asserted */
#define	__SRW	0x0010		/* open for reading & writing */
#define	__SEOF	0x0020		/* found EOF */
#define	__SERR	0x0040		/* found error */
#define	__SMBF	0x0080		/* _buf is from malloc */
#define	__SAPP	0x0100		/* fdopen()ed in append mode */
#define	__SSTR	0x0200		/* this is an sprintf/snprintf string */
#define	__SOPT	0x0400		/* do fseek() optimisation */
#define	__SNPT	0x0800		/* do not do fseek() optimisation */
#define	__SOFF	0x1000		/* set iff _offset is in fact correct */
#define	__SMOD	0x2000		/* true => fgetln modified _p text */
#define	__SALC	0x4000		/* allocate string space dynamically */

/*
 * The following three definitions are for ANSI C, which took them
 * from System V, which brilliantly took internal interface macros and
 * made them official arguments to setvbuf(), without renaming them.
 * Hence, these ugly _IOxxx names are *supposed* to appear in user code.
 *
 * Although numbered as their counterparts above, the implementation
 * does not rely on this.
 */
#define	_IOFBF	0		/* setvbuf should set fully buffered */
#define	_IOLBF	1		/* setvbuf should set line buffered */
#define	_IONBF	2		/* setvbuf should set unbuffered */

#define	BUFSIZ	1024		/* size of buffer used by setbuf */

#define	EOF	(-1)

/*
 * FOPEN_MAX is a minimum maximum, and should be the number of descriptors
 * that the kernel can provide without allocation of a resource that can
 * fail without the process sleeping.  Do not use this for anything.
 */
#define	FOPEN_MAX	20	/* must be <= OPEN_MAX <sys/syslimits.h> */
#define	FILENAME_MAX	1024	/* must be <= PATH_MAX <sys/syslimits.h> */

/* System V/ANSI C; this is the wrong way to do this, do *not* use these. */
#if __BSD_VISIBLE || __XPG_VISIBLE
#define	P_tmpdir	"/tmp/"
#endif
#define	L_tmpnam	1024	/* XXX must be == PATH_MAX */
#define	TMP_MAX		308915776

#ifndef SEEK_SET
#define	SEEK_SET	0	/* set file offset to offset */
#endif
#ifndef SEEK_CUR
#define	SEEK_CUR	1	/* set file offset to current plus offset */
#endif
#ifndef SEEK_END
#define	SEEK_END	2	/* set file offset to EOF plus offset */
#endif

#define	stdin	(&__sF[0])
#define	stdout	(&__sF[1])
#define	stderr	(&__sF[2])

/*
 * Functions defined in ANSI C standard.
 */
__BEGIN_DECLS
void	 clearerr(FILE *);
int	 fclose(FILE *);
int	 feof(FILE *);
int	 ferror(FILE *);
int	 fflush(FILE *);
int	 fgetc(FILE *);
int	 fgetpos(FILE *, fpos_t *);
char	*fgets(char *, int, FILE *);
FILE	*fopen(const char *, const char *);
int	 fprintf(FILE *, const char *, ...);
int	 fputc(int, FILE *);
int	 fputs(const char *, FILE *);
size_t	 fread(void *, size_t, size_t, FILE *);
FILE	*freopen(const char *, const char *, FILE *);
int	 fscanf(FILE *, const char *, ...);
int	 fseek(FILE *, long, int);
int	 fseeko(FILE *, off_t, int);
int	 fsetpos(FILE *, const fpos_t *);
long	 ftell(FILE *);
off_t	 ftello(FILE *);
size_t	 fwrite(const void *, size_t, size_t, FILE *);
int	 getc(FILE *);
int	 getchar(void);
char	*gets(char *);
#if __BSD_VISIBLE && !defined(__SYS_ERRLIST)
#define __SYS_ERRLIST

extern int sys_nerr;			/* perror(3) external variables */
extern char *sys_errlist[];
#endif
void	 perror(const char *);
int	 printf(const char *, ...);
int	 putc(int, FILE *);
int	 putchar(int);
int	 puts(const char *);
int	 remove(const char *);
int	 rename(const char *, const char *);
void	 rewind(FILE *);
int	 scanf(const char *, ...);
void	 setbuf(FILE *, char *);
int	 setvbuf(FILE *, char *, int, size_t);
int	 sprintf(char *, const char *, ...);
int	 sscanf(const char *, const char *, ...);
FILE	*tmpfile(void);
char	*tmpnam(char *);
int	 ungetc(int, FILE *);
int	 vfprintf(FILE *, const char *, __va_list);
int	 vprintf(const char *, __va_list);
int	 vsprintf(char *, const char *, __va_list);

#if __ISO_C_VISIBLE >= 1999 || __BSD_VISIBLE
int	 snprintf(char *, size_t, const char *, ...)
		__attribute__((__format__ (printf, 3, 4)))
		__attribute__((__nonnull__ (3)));
int	 vfscanf(FILE *, const char *, __va_list)
		__attribute__((__format__ (scanf, 2, 0)))
		__attribute__((__nonnull__ (2)));
int	 vscanf(const char *, __va_list)
		__attribute__((__format__ (scanf, 1, 0)))
		__attribute__((__nonnull__ (1)));
int	 vsnprintf(char *, size_t, const char *, __va_list)
		__attribute__((__format__ (printf, 3, 0)))
		__attribute__((__nonnull__ (3)));
int	 vsscanf(const char *, const char *, __va_list)
		__attribute__((__format__ (scanf, 2, 0)))
		__attribute__((__nonnull__ (2)));
#endif /* __ISO_C_VISIBLE >= 1999 || __BSD_VISIBLE */

__END_DECLS


/*
 * Functions defined in POSIX 1003.1.
 */
#if __BSD_VISIBLE || __POSIX_VISIBLE || __XPG_VISIBLE
#define	L_ctermid	1024	/* size for ctermid(); PATH_MAX */
#define L_cuserid	9	/* size for cuserid(); UT_NAMESIZE + 1 */

__BEGIN_DECLS
char	*ctermid(char *);
char	*cuserid(char *);
FILE	*fdopen(int, const char *);
int	 fileno(FILE *);

#if (__POSIX_VISIBLE >= 199209) || 1 /* ANDROID: Bionic does include this */
int	 pclose(FILE *);
FILE	*popen(const char *, const char *);
#endif

#if __POSIX_VISIBLE >= 199506
void	 flockfile(FILE *);
int	 ftrylockfile(FILE *);
void	 funlockfile(FILE *);

/*
 * These are normally used through macros as defined below, but POSIX
 * requires functions as well.
 */
int	 getc_unlocked(FILE *);
int	 getchar_unlocked(void);
int	 putc_unlocked(int, FILE *);
int	 putchar_unlocked(int);
#endif /* __POSIX_VISIBLE >= 199506 */

#if __XPG_VISIBLE
char	*tempnam(const char *, const char *);
#endif
__END_DECLS

#endif /* __BSD_VISIBLE || __POSIX_VISIBLE || __XPG_VISIBLE */

/*
 * Routines that are purely local.
 */
#if __BSD_VISIBLE
__BEGIN_DECLS
int	 asprintf(char **, const char *, ...)
		__attribute__((__format__ (printf, 2, 3)))
		__attribute__((__nonnull__ (2)));
char	*fgetln(FILE *, size_t *);
int	 fpurge(FILE *);
int	 getw(FILE *);
int	 putw(int, FILE *);
void	 setbuffer(FILE *, char *, int);
int	 setlinebuf(FILE *);
int	 vasprintf(char **, const char *, __va_list)
		__attribute__((__format__ (printf, 2, 0)))
		__attribute__((__nonnull__ (2)));
__END_DECLS

/*
 * Stdio function-access interface.
 */
__BEGIN_DECLS
FILE	*funopen(const void *,
		int (*)(void *, char *, int),
		int (*)(void *, const char *, int),
		fpos_t (*)(void *, fpos_t, int),
		int (*)(void *));
__END_DECLS
#define	fropen(cookie, fn) funopen(cookie, fn, 0, 0, 0)
#define	fwopen(cookie, fn) funopen(cookie, 0, fn, 0, 0)
#endif /* __BSD_VISIBLE */

/*
 * Functions internal to the implementation.
 */
__BEGIN_DECLS
int	__srget(FILE *);
int	__swbuf(int, FILE *);
__END_DECLS

/*
 * The __sfoo macros are here so that we can
 * define function versions in the C library.
 */
#define	__sgetc(p) (--(p)->_r < 0 ? __srget(p) : (int)(*(p)->_p++))
#if defined(__GNUC__)
static __inline int __sputc(int _c, FILE *_p) {
	if (--_p->_w >= 0 || (_p->_w >= _p->_lbfsize && (char)_c != '\n'))
		return (*_p->_p++ = _c);
	else
		return (__swbuf(_c, _p));
}
#else
/*
 * This has been tuned to generate reasonable code on the vax using pcc.
 */
#define	__sputc(c, p) \
	(--(p)->_w < 0 ? \
		(p)->_w >= (p)->_lbfsize ? \
			(*(p)->_p = (c)), *(p)->_p != '\n' ? \
				(int)*(p)->_p++ : \
				__swbuf('\n', p) : \
			__swbuf((int)(c), p) : \
		(*(p)->_p = (c), (int)*(p)->_p++))
#endif

#define	__sfeof(p)	(((p)->_flags & __SEOF) != 0)
#define	__sferror(p)	(((p)->_flags & __SERR) != 0)
#define	__sclearerr(p)	((void)((p)->_flags &= ~(__SERR|__SEOF)))
#define	__sfileno(p)	((p)->_file)

#define	feof(p)		__sfeof(p)
#define	ferror(p)	__sferror(p)

#ifndef _POSIX_THREADS
#define	clearerr(p)	__sclearerr(p)
#endif

#if __POSIX_VISIBLE
#define	fileno(p)	__sfileno(p)
#endif

#ifndef lint
#ifndef _POSIX_THREADS
#define	getc(fp)	__sgetc(fp)
#endif /* _POSIX_THREADS */
#define	getc_unlocked(fp)	__sgetc(fp)
/*
 * The macro implementations of putc and putc_unlocked are not
 * fully POSIX compliant; they do not set errno on failure
 */
#if __BSD_VISIBLE
#ifndef _POSIX_THREADS
#define putc(x, fp)	__sputc(x, fp)
#endif /* _POSIX_THREADS */
#define putc_unlocked(x, fp)	__sputc(x, fp)
#endif /* __BSD_VISIBLE */
#endif /* lint */

#define	getchar()	getc(stdin)
#define	putchar(x)	putc(x, stdout)
#define getchar_unlocked()	getc_unlocked(stdin)
#define putchar_unlocked(c)	putc_unlocked(c, stdout)

#ifdef _GNU_SOURCE
/*
 * glibc defines dprintf(int, const char*, ...), which is poorly named
 * and likely to conflict with locally defined debugging printfs
 * fdprintf is a better name, and some programs that use fdprintf use a
 * #define fdprintf dprintf for compatibility
 */
int fdprintf(int, const char*, ...);
int vfdprintf(int, const char*, __va_list);
#endif /* _GNU_SOURCE */

#endif /* _STDIO_H_ */
