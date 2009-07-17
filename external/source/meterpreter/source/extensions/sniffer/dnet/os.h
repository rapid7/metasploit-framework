/*
 * os.h
 *
 * Sleazy OS-specific defines.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: os.h,v 1.12 2005/02/15 05:31:00 dugsong Exp $
 */

#ifndef DNET_OS_H
#define DNET_OS_H

#ifdef _WIN32
# include <winsock2.h>
# include <windows.h>
/* XXX */
# undef IP_OPT_LSRR
# undef IP_OPT_TS
# undef IP_OPT_RR
# undef IP_OPT_SSRR
  typedef u_char	uint8_t;
  typedef u_short	uint16_t;
  typedef u_int		uint32_t;
# ifndef __CYGWIN__
  typedef long		ssize_t;
# endif
#else
# include <sys/param.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
# ifdef __bsdi__
#  include <machine/types.h>
   typedef u_int8_t	uint8_t;
   typedef u_int16_t	uint16_t;
   typedef u_int32_t	uint32_t;
   typedef u_int64_t	uint64_t;
# else
#  include <inttypes.h>
# endif
#endif

#define DNET_LIL_ENDIAN		1234
#define DNET_BIG_ENDIAN		4321

/* BSD and IRIX */
#ifdef BYTE_ORDER
#if BYTE_ORDER == LITTLE_ENDIAN
# define DNET_BYTESEX		DNET_LIL_ENDIAN
#elif BYTE_ORDER == BIG_ENDIAN
# define DNET_BYTESEX		DNET_BIG_ENDIAN
#endif
#endif

/* Linux */
#ifdef __BYTE_ORDER
#if __BYTE_ORDER == __LITTLE_ENDIAN
# define DNET_BYTESEX		DNET_LIL_ENDIAN
#elif __BYTE_ORDER == __BIG_ENDIAN
# define DNET_BYTESEX		DNET_BIG_ENDIAN
#endif
#endif

/* Solaris */
#if defined(_BIT_FIELDS_LTOH)
# define DNET_BYTESEX		DNET_LIL_ENDIAN
#elif defined (_BIT_FIELDS_HTOL)
# define DNET_BYTESEX		DNET_BIG_ENDIAN
#endif

/* Win32 - XXX */
#ifdef _WIN32
# define DNET_BYTESEX		DNET_LIL_ENDIAN
#endif

/* Nastiness from old BIND code. */
#ifndef DNET_BYTESEX
# if defined(vax) || defined(ns32000) || defined(sun386) || defined(i386) || \
    defined(MIPSEL) || defined(_MIPSEL) || defined(BIT_ZERO_ON_RIGHT) || \
    defined(__alpha__) || defined(__alpha)
#  define DNET_BYTESEX		DNET_LIL_ENDIAN
# elif defined(sel) || defined(pyr) || defined(mc68000) || defined(sparc) || \
    defined(is68k) || defined(tahoe) || defined(ibm032) || defined(ibm370) || \
    defined(MIPSEB) || defined(_MIPSEB) || defined(_IBMR2) || defined(DGUX) ||\
    defined(apollo) || defined(__convex__) || defined(_CRAY) || \
    defined(__hppa) || defined(__hp9000) || \
    defined(__hp9000s300) || defined(__hp9000s700) || defined(__ia64) || \
    defined (BIT_ZERO_ON_LEFT) || defined(m68k)
#  define DNET_BYTESEX		DNET_BIG_ENDIAN
# else
#  error "bytesex unknown"
# endif
#endif

/* C++ support. */
#undef __BEGIN_DECLS
#undef __END_DECLS
#ifdef __cplusplus
# define __BEGIN_DECLS	extern "C" {
# define __END_DECLS	} /* extern "C" */
#else
# define __BEGIN_DECLS
# define __END_DECLS
#endif

/* Support for flexible arrays. */
#undef __flexarr
#if defined(__GNUC__) && ((__GNUC__ > 2) || (__GNUC__ == 2 && __GNUC_MINOR__ >= 97))
/* GCC 2.97 supports C99 flexible array members.  */
# define __flexarr	[]
#else
# ifdef __GNUC__
#  define __flexarr	[0]
# else
#  if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#   define __flexarr	[]
#  elif defined(_WIN32)
/* MS VC++ */
#   define __flexarr	[]
#  else
/* Some other non-C99 compiler. Approximate with [1]. */
#   define __flexarr	[1]
#  endif
# endif
#endif

#endif /* DNET_OS_H */
