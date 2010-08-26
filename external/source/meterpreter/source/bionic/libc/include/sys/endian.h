/*	$OpenBSD: endian.h,v 1.17 2006/01/06 18:53:05 millert Exp $	*/

/*-
 * Copyright (c) 1997 Niklas Hallqvist.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Generic definitions for little- and big-endian systems.  Other endianesses
 * has to be dealt with in the specific machine/endian.h file for that port.
 *
 * This file is meant to be included from a little- or big-endian port's
 * machine/endian.h after setting _BYTE_ORDER to either 1234 for little endian
 * or 4321 for big..
 */

#ifndef _SYS_ENDIAN_H_
#define _SYS_ENDIAN_H_

#include <sys/cdefs.h>
#include <machine/_types.h>

#define _LITTLE_ENDIAN	1234
#define _BIG_ENDIAN	4321
#define _PDP_ENDIAN	3412

#if __BSD_VISIBLE
#define LITTLE_ENDIAN	_LITTLE_ENDIAN
#define BIG_ENDIAN	_BIG_ENDIAN
#define PDP_ENDIAN	_PDP_ENDIAN
#define BYTE_ORDER	_BYTE_ORDER
#endif

#ifdef __GNUC__

#define __swap16gen(x) __statement({					\
	__uint16_t __swap16gen_x = (x);					\
									\
	(__uint16_t)((__swap16gen_x & 0xff) << 8 |			\
	    (__swap16gen_x & 0xff00) >> 8);				\
})

#define __swap32gen(x) __statement({					\
	__uint32_t __swap32gen_x = (x);					\
									\
	(__uint32_t)((__swap32gen_x & 0xff) << 24 |			\
	    (__swap32gen_x & 0xff00) << 8 |				\
	    (__swap32gen_x & 0xff0000) >> 8 |				\
	    (__swap32gen_x & 0xff000000) >> 24);			\
})

#define __swap64gen(x) __statement({					\
	__uint64_t __swap64gen_x = (x);					\
									\
	(__uint64_t)((__swap64gen_x & 0xff) << 56 |			\
	    (__swap64gen_x & 0xff00ULL) << 40 |				\
	    (__swap64gen_x & 0xff0000ULL) << 24 |			\
	    (__swap64gen_x & 0xff000000ULL) << 8 |			\
	    (__swap64gen_x & 0xff00000000ULL) >> 8 |			\
	    (__swap64gen_x & 0xff0000000000ULL) >> 24 |			\
	    (__swap64gen_x & 0xff000000000000ULL) >> 40 |		\
	    (__swap64gen_x & 0xff00000000000000ULL) >> 56);		\
})

#else /* __GNUC__ */

/* Note that these macros evaluate their arguments several times.  */
#define __swap16gen(x)							\
    (__uint16_t)(((__uint16_t)(x) & 0xff) << 8 | ((__uint16_t)(x) & 0xff00) >> 8)

#define __swap32gen(x)							\
    (__uint32_t)(((__uint32_t)(x) & 0xff) << 24 |			\
    ((__uint32_t)(x) & 0xff00) << 8 | ((__uint32_t)(x) & 0xff0000) >> 8 |\
    ((__uint32_t)(x) & 0xff000000) >> 24)

#define __swap64gen(x)							\
	(__uint64_t)((((__uint64_t)(x) & 0xff) << 56) |			\
	    ((__uint64_t)(x) & 0xff00ULL) << 40 |			\
	    ((__uint64_t)(x) & 0xff0000ULL) << 24 |			\
	    ((__uint64_t)(x) & 0xff000000ULL) << 8 |			\
	    ((__uint64_t)(x) & 0xff00000000ULL) >> 8 |			\
	    ((__uint64_t)(x) & 0xff0000000000ULL) >> 24 |		\
	    ((__uint64_t)(x) & 0xff000000000000ULL) >> 40 |		\
	    ((__uint64_t)(x) & 0xff00000000000000ULL) >> 56)

#endif /* __GNUC__ */

/*
 * Define MD_SWAP if you provide swap{16,32}md functions/macros that are
 * optimized for your architecture,  These will be used for swap{16,32}
 * unless the argument is a constant and we are using GCC, where we can
 * take advantage of the CSE phase much better by using the generic version.
 */
#ifdef MD_SWAP
#if __GNUC__

#define __swap16(x) __statement({					\
	__uint16_t __swap16_x = (x);					\
									\
	__builtin_constant_p(x) ? __swap16gen(__swap16_x) :		\
	    __swap16md(__swap16_x);					\
})

#define __swap32(x) __statement({					\
	__uint32_t __swap32_x = (x);					\
									\
	__builtin_constant_p(x) ? __swap32gen(__swap32_x) :		\
	    __swap32md(__swap32_x);					\
})

#define __swap64(x) __statement({					\
	__uint64_t __swap64_x = (x);					\
									\
	__builtin_constant_p(x) ? __swap64gen(__swap64_x) :		\
	    __swap64md(__swap64_x);					\
})

#endif /* __GNUC__  */

#else /* MD_SWAP */
#define __swap16 __swap16gen
#define __swap32 __swap32gen
#define __swap64 __swap64gen
#endif /* MD_SWAP */

#define __swap16_multi(v, n) do {						\
	__size_t __swap16_multi_n = (n);				\
	__uint16_t *__swap16_multi_v = (v);				\
									\
	while (__swap16_multi_n) {					\
		*__swap16_multi_v = swap16(*__swap16_multi_v);		\
		__swap16_multi_v++;					\
		__swap16_multi_n--;					\
	}								\
} while (0)

#if __BSD_VISIBLE
#define swap16 __swap16
#define swap32 __swap32
#define swap64 __swap64
#define swap16_multi __swap16_multi

__BEGIN_DECLS
__uint64_t	htobe64(__uint64_t);
__uint32_t	htobe32(__uint32_t);
__uint16_t	htobe16(__uint16_t);
__uint64_t	betoh64(__uint64_t);
__uint32_t	betoh32(__uint32_t);
__uint16_t	betoh16(__uint16_t);

__uint64_t	htole64(__uint64_t);
__uint32_t	htole32(__uint32_t);
__uint16_t	htole16(__uint16_t);
__uint64_t	letoh64(__uint64_t);
__uint32_t	letoh32(__uint32_t);
__uint16_t	letoh16(__uint16_t);
__END_DECLS
#endif /* __BSD_VISIBLE */

#if _BYTE_ORDER == _LITTLE_ENDIAN

/* Can be overridden by machine/endian.h before inclusion of this file.  */
#ifndef _QUAD_HIGHWORD
#define _QUAD_HIGHWORD 1
#endif
#ifndef _QUAD_LOWWORD
#define _QUAD_LOWWORD 0
#endif

#if __BSD_VISIBLE
#define htobe16 __swap16
#define htobe32 __swap32
#define htobe64 __swap64
#define betoh16 __swap16
#define betoh32 __swap32
#define betoh64 __swap64

#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)
#define letoh16(x) (x)
#define letoh32(x) (x)
#define letoh64(x) (x)
#endif /* __BSD_VISIBLE */

#define htons(x) __swap16(x)
#define htonl(x) __swap32(x)
#define ntohs(x) __swap16(x)
#define ntohl(x) __swap32(x)

/* Bionic additions */
#define ntohq(x) __swap64(x)
#define htonq(x) __swap64(x)

#define __LITTLE_ENDIAN_BITFIELD

#endif /* _BYTE_ORDER */

#if _BYTE_ORDER == _BIG_ENDIAN

/* Can be overridden by machine/endian.h before inclusion of this file.  */
#ifndef _QUAD_HIGHWORD
#define _QUAD_HIGHWORD 0
#endif
#ifndef _QUAD_LOWWORD
#define _QUAD_LOWWORD 1
#endif

#if __BSD_VISIBLE
#define htole16 __swap16
#define htole32 __swap32
#define htole64 __swap64
#define letoh16 __swap16
#define letoh32 __swap32
#define letoh64 __swap64

#define htobe16(x) (x)
#define htobe32(x) (x)
#define htobe64(x) (x)
#define betoh16(x) (x)
#define betoh32(x) (x)
#define betoh64(x) (x)
#endif /* __BSD_VISIBLE */

#define htons(x) (x)
#define htonl(x) (x)
#define ntohs(x) (x)
#define ntohl(x) (x)

/* Bionic additions */
#define ntohq(x) (x)
#define htonq(x) (x)

#define __BIG_ENDIAN_BITFIELD

#endif /* _BYTE_ORDER */

#if __BSD_VISIBLE
#define	NTOHL(x) (x) = ntohl((u_int32_t)(x))
#define	NTOHS(x) (x) = ntohs((u_int16_t)(x))
#define	HTONL(x) (x) = htonl((u_int32_t)(x))
#define	HTONS(x) (x) = htons((u_int16_t)(x))
#endif


#define  __BYTE_ORDER       _BYTE_ORDER
#ifndef  __LITTLE_ENDIAN
#define  __LITTLE_ENDIAN    _LITTLE_ENDIAN
#endif
#ifndef  __BIG_ENDIAN
#define  __BIG_ENDIAN       _BIG_ENDIAN
#endif

#endif /* _SYS_ENDIAN_H_ */
