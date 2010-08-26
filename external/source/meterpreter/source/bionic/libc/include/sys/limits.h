/* $OpenBSD: limits.h,v 1.6 2005/12/13 00:35:23 millert Exp $ */
/*
 * Copyright (c) 2002 Marc Espie.
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
 * THIS SOFTWARE IS PROVIDED BY THE OPENBSD PROJECT AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OPENBSD
 * PROJECT OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _SYS_LIMITS_H_
#define _SYS_LIMITS_H_

#include <sys/cdefs.h>
#include <linux/limits.h>

/* Common definitions for limits.h. */

/*
 * <machine/internal_types.h> is meant to describe a specific architecture,
 * but to be a safe include, that doesn't ever define anything that is
 * user-visible (only typedefs and #define names that stays in the __xxx
 * namespace).
 *
 *   __machine_has_unsigned_chars	(default is signed chars)
 *   __FLT_xxx/__DBL_xxx		non standard values for floating
 *   					points limits.
 */
#include <machine/internal_types.h>

/* Legacy */
#include <machine/limits.h>

#define	CHAR_BIT	8		/* number of bits in a char */

#define	SCHAR_MAX	0x7f		/* max value for a signed char */
#define SCHAR_MIN	(-0x7f-1)	/* min value for a signed char */

#define	UCHAR_MAX	0xffU		/* max value for an unsigned char */
#ifdef __machine_has_unsigned_chars
# define CHAR_MIN	0		/* min value for a char */
# define CHAR_MAX	0xff		/* max value for a char */
#else
# define CHAR_MAX	0x7f
# define CHAR_MIN	(-0x7f-1)
#endif

#define	USHRT_MAX	0xffffU		/* max value for an unsigned short */
#define	SHRT_MAX	0x7fff		/* max value for a short */
#define SHRT_MIN        (-0x7fff-1)     /* min value for a short */

#define	UINT_MAX	0xffffffffU	/* max value for an unsigned int */
#define	INT_MAX		0x7fffffff	/* max value for an int */
#define	INT_MIN		(-0x7fffffff-1)	/* min value for an int */

#ifdef __LP64__
# define ULONG_MAX	0xffffffffffffffffUL
					/* max value for unsigned long */
# define LONG_MAX	0x7fffffffffffffffL
					/* max value for a signed long */
# define LONG_MIN	(-0x7fffffffffffffffL-1)
					/* min value for a signed long */
#else
# define ULONG_MAX	0xffffffffUL	/* max value for an unsigned long */
# define LONG_MAX	0x7fffffffL	/* max value for a long */
# define LONG_MIN	(-0x7fffffffL-1)/* min value for a long */
#endif

#if __BSD_VISIBLE || __ISO_C_VISIBLE >= 1999
# define ULLONG_MAX	0xffffffffffffffffULL
					/* max value for unsigned long long */
# define LLONG_MAX	0x7fffffffffffffffLL
					/* max value for a signed long long */
# define LLONG_MIN	(-0x7fffffffffffffffLL-1)
					/* min value for a signed long long */
#endif

#if __BSD_VISIBLE
# define UID_MAX	UINT_MAX	/* max value for a uid_t */
# define GID_MAX	UINT_MAX	/* max value for a gid_t */
#endif


#ifdef __LP64__
# define LONG_BIT	64
#else
# define LONG_BIT	32
#endif

/* float.h defines these as well */
# if !defined(DBL_DIG)
#  if defined(__DBL_DIG)
#   define DBL_DIG	__DBL_DIG
#   define DBL_MAX	__DBL_MAX
#   define DBL_MIN	__DBL_MIN

#   define FLT_DIG	__FLT_DIG
#   define FLT_MAX	__FLT_MAX
#   define FLT_MIN	__FLT_MIN
#  else
#   define DBL_DIG	15
#   define DBL_MAX	1.7976931348623157E+308
#   define DBL_MIN	2.2250738585072014E-308

#   define FLT_DIG	6
#   define FLT_MAX	3.40282347E+38F
#   define FLT_MIN	1.17549435E-38F
#  endif
# endif

/* Bionic: the following has been optimized out from our processed kernel headers */

#define  CHILD_MAX   999
#define  OPEN_MAX    256

/* Bionic-specific definitions */

#define  _POSIX_VERSION             200112L   /* Posix C language bindings version */
#define  _POSIX2_VERSION            -1        /* we don't support Posix command-line tools */
#define  _POSIX2_C_VERSION          _POSIX_VERSION
#define  _XOPEN_VERSION             500       /* by Posix definition */
#define  _XOPEN_XCU_VERSION         -1        /* we don't support command-line utilities */

/* tell what we implement legacy stuff when appropriate */
#if _POSIX_VERSION > 0
#define  _XOPEN_XPG2                1
#define  _XOPEN_XPG3                1
#define  _XOPEN_XPG4                1
#define  _XOPEN_UNIX                1
#endif

#define  _XOPEN_ENH_I18N          -1  /* we don't support internationalization in the C library */
#define  _XOPEN_CRYPT             -1  /* don't support X/Open Encryption */
#define  _XOPEN_LEGACY            -1  /* don't claim we support these, we have some of them but not all */
#define  _XOPEN_REALTIME          -1 /* we don't support all these functions */
#define  _XOPEN_REALTIME_THREADS  -1  /* same here */

#define  _POSIX_REALTIME_SIGNALS    -1  /* for now, this is not supported */
#define  _POSIX_PRIORITY_SCHEDULING  1  /* priority scheduling is a Linux feature */
#define  _POSIX_TIMERS               1  /* Posix timers are supported */
#undef   _POSIX_ASYNCHRONOUS_IO         /* aio_ functions are not supported */
#define  _POSIX_SYNCHRONIZED_IO      1  /* synchronized i/o supported */
#define  _POSIX_FSYNC                1  /* fdatasync() supported */
#define  _POSIX_MAPPED_FILES         1  /* mmap-ed files supported */

/* XXX: TODO: complete and check list here */


#define  _POSIX_THREADS             1    /* we support threads */
#define  _POSIX_THREAD_STACKADDR    1    /* we support thread stack address */
#define  _POSIX_THREAD_STACKSIZE    1    /* we support thread stack size */
#define  _POSIX_THREAD_PRIO_INHERIT 200112L   /* linux feature */
#define  _POSIX_THREAD_PRIO_PROTECT 200112L   /* linux feature */

#undef   _POSIX_PROCESS_SHARED           /* we don't support process-shared synchronization */
#undef   _POSIX_THREAD_SAFE_FUNCTIONS    /* most functions are, but not everything yet */
#define  _POSIX_CHOWN_RESTRICTED    1    /* yes, chown requires appropriate priviledges */
#define  _POSIX_NO_TRUNC            1    /* very long pathnames generate an error */
#define  _POSIX_SAVED_IDS           1    /* saved user ids is a Linux feature */
#define  _POSIX_JOB_CONTROL         1    /* job control is a Linux feature */



#endif
