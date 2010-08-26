/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _STDINT_H
#define _STDINT_H

#include <stddef.h>
#include <sys/_types.h>



#if !defined(__cplusplus) || defined(__STDC_LIMIT_MACROS)
#  define __STDINT_LIMITS
#endif

#if !defined(__cplusplus) || defined(__STDC_CONSTANT_MACROS)
#  define  __STDINT_MACROS
#endif

/* the definitions of STDINT_LIMITS depend on those of STDINT_MACROS */
#if defined __STDINT_LIMITS && !defined __STDINT_MACROS
#  define  __STDINT_MACROS
#endif

#if !defined __STRICT_ANSI__ || __STDC_VERSION__ >= 199901L
#  define __STDC_INT64__
#endif

typedef __int8_t      int8_t;
typedef __uint8_t     uint8_t;
typedef __int16_t     int16_t;
typedef __uint16_t    uint16_t;
typedef __int32_t     int32_t;
typedef __uint32_t    uint32_t;
#if defined(__STDC_INT64__)
typedef __int64_t     int64_t;
typedef __uint64_t    uint64_t;

#endif

/*
 * int8_t & uint8_t
 */

//typedef int8_t        int_least8_t; PKS .. remote_dispatch problem
//typedef int8_t        int_fast8_t;

typedef uint8_t       uint_least8_t;
typedef uint8_t       uint_fast8_t;

#ifdef __STDINT_LIMITS
#  define INT8_MIN         (-128)
#  define INT8_MAX         (127)
#  define INT_LEAST8_MIN   INT8_MIN
#  define INT_LEAST8_MAX   INT8_MAX
#  define INT_FAST8_MIN    INT8_MIN
#  define INT_FAST8_MAX    INT8_MAX

#  define UINT8_MAX           (255U)
#  define UINT_LEAST8_MAX     UINT8_MAX
#  define UINT_FAST8_MAX      UINT8_MAX
#endif

#ifdef __STDINT_MACROS
#  define INT8_C(c)	c
#  define INT_LEAST8_C(c)	 INT8_C(c)
#  define INT_FAST8_C(c)	INT8_C(c)

#  define UINT8_C(c)	c ## U
#  define UINT_LEAST8_C(c)  UINT8_C(c)
#  define UINT_FAST8_C(c)  UINT8_C(c)
#endif

/*
 * int16_t & uint16_t
 */


typedef int16_t       int_least16_t;
typedef int32_t       int_fast16_t;

typedef uint16_t      uint_least16_t;
typedef uint32_t      uint_fast16_t;

#ifdef __STDINT_LIMITS
#  define INT16_MIN	(-32768)
#  define INT16_MAX	(32767)
#  define INT_LEAST16_MIN	INT16_MIN
#  define INT_LEAST16_MAX	INT16_MAX
#  define INT_FAST16_MIN	INT32_MIN
#  define INT_FAST16_MAX	INT32_MAX

#  define UINT16_MAX	(65535U)
#  define UINT_LEAST16_MAX UINT16_MAX
#  define UINT_FAST16_MAX UINT32_MAX
#endif

#ifdef __STDINT_MACROS
#  define INT16_C(c)	c
#  define INT_LEAST16_C(c) INT16_C(c)
#  define INT_FAST16_C(c)	 INT32_C(c)

#  define UINT16_C(c)	c ## U
#  define UINT_LEAST16_C(c) UINT16_C(c)
#  define UINT_FAST16_C(c) UINT32_C(c)
#endif

/*
 * int32_t & uint32_t
 */

typedef int32_t       int_least32_t;
typedef int32_t       int_fast32_t;

typedef uint32_t      uint_least32_t;
typedef uint32_t      uint_fast32_t;

#ifdef __STDINT_LIMITS
#  define INT32_MIN	(-2147483647-1)
#  define INT32_MAX	(2147483647)
#  define INT_LEAST32_MIN	INT32_MIN
#  define INT_LEAST32_MAX	INT32_MAX
#  define INT_FAST32_MIN	INT32_MIN
#  define INT_FAST32_MAX	INT32_MAX

#  define UINT32_MAX	(4294967295U)
#  define UINT_LEAST32_MAX UINT32_MAX
#  define UINT_FAST32_MAX UINT32_MAX
#endif

#ifdef __STDINT_MACROS
#  define INT32_C(c)	c
#  define INT_LEAST32_C(c) INT32_C(c)
#  define INT_FAST32_C(c)  INT32_C(c)

#  define UINT32_C(c)	c ## U
#  define UINT_LEAST32_C(c) UINT32_C(c)
#  define UINT_FAST32_C(c) UINT32_C(c)
#endif

#if defined(__STDC_INT64__)
/*
 *  int64_t
 */
typedef int64_t       int_least64_t;
typedef int64_t       int_fast64_t;

typedef uint64_t      uint_least64_t;
typedef uint64_t      uint_fast64_t;


#ifdef __STDINT_LIMITS
#  define INT64_MIN        (__INT64_C(-9223372036854775807)-1)
#  define INT64_MAX        (__INT64_C(9223372036854775807))
#  define INT_LEAST64_MIN  INT64_MIN
#  define INT_LEAST64_MAX  INT64_MAX
#  define INT_FAST64_MIN   INT64_MIN
#  define INT_FAST64_MAX   INT64_MAX
#  define UINT64_MAX       (__UINT64_C(18446744073709551615))

#  define UINT_LEAST64_MAX UINT64_MAX
#  define UINT_FAST64_MAX UINT64_MAX
#endif

#ifdef __STDINT_MACROS
#  define __INT64_C(c)     c ## LL
#  define INT64_C(c)       __INT64_C(c)
#  define INT_LEAST64_C(c) INT64_C(c)
#  define INT_FAST64_C(c)  INT64_C(c)

#  define __UINT64_C(c)     c ## ULL
#  define UINT64_C(c)       __UINT64_C(c)
#  define UINT_LEAST64_C(c) UINT64_C(c)
#  define UINT_FAST64_C(c)  UINT64_C(c)
#endif


#  define __PRI64_RANK   "ll"
#  define __PRIFAST_RANK ""
#  define __PRIPTR_RANK  ""

#endif /* __STDC_INT64__ */

/*
 * intptr_t & uintptr_t
 */

typedef int           intptr_t;
typedef unsigned int  uintptr_t;

#  define INTPTR_MIN    INT32_MIN
#  define INTPTR_MAX    INT32_MAX
#  define UINTPTR_MAX   UINT32_MAX
#  define INTPTR_C(c)   INT32_C(c)
#  define UINTPTR_C(c)  UINT32_C(c)
#  define PTRDIFF_C(c)  INT32_C(c)
#  define PTRDIFF_MIN   INT32_MIN
#  define PTRDIFF_MAX   INT32_MAX


/*
 *  intmax_t & uintmax_t
 */

#if defined(__STDC_INT64__)

typedef uint64_t uintmax_t;
typedef int64_t  intmax_t;

#define INTMAX_MIN	INT64_MIN
#define INTMAX_MAX	INT64_MAX
#define UINTMAX_MAX	UINT64_MAX

#define INTMAX_C(c)	INT64_C(c)
#define UINTMAX_C(c)	UINT64_C(c)

#else /* !__STDC_INT64__ */

typedef uint32_t  uintmax_t;
typedef int32_t   intmax_t;

#define  INTMAX_MIN    INT32_MIN
#define  INTMAX_MAX    INT32_MAX
#define  UINTMAX_MAX   UINT32_MAX

#define INTMAX_C(c)	INT32_C(c)
#define UINTMAX_C(c)	UINT32_C(c)

#endif /* !__STDC_INT64__ */


/* size_t is defined by the GCC-specific <stddef.h> */
#ifndef _SSIZE_T_DEFINED_
#define _SSIZE_T_DEFINED_
typedef long int  ssize_t;
#endif

#define _BITSIZE 32

/* Keep the kernel from trying to define these types... */
#define __BIT_TYPES_DEFINED__

#endif /* _STDINT_H */
