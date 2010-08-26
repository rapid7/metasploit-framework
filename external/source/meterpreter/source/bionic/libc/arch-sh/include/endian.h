/*	$OpenBSD: endian.h,v 1.1.1.1 2006/10/06 21:02:55 miod Exp $	*/
/*	$NetBSD: endian.h,v 1.4 2000/03/17 00:09:25 mycroft Exp $	*/

/* Written by Manuel Bouyer. Public domain */

#ifndef _SH_ENDIAN_H_
#define	_SH_ENDIAN_H_

#ifdef  __GNUC__

#define	__swap64md	__swap64gen

#define __swap16md(x) ({						\
	uint16_t rval;							\
									\
	__asm volatile ("swap.b %1,%0" : "=r"(rval) : "r"(x));		\
									\
	rval;								\
})

#define __swap32md(x) ({						\
	uint32_t rval;							\
									\
	__asm volatile ("swap.b %1,%0; swap.w %0,%0; swap.b %0,%0"	\
			  : "=r"(rval) : "r"(x));			\
									\
	rval;								\
})

#define MD_SWAP

#endif /* __GNUC_ */

#define	_BYTE_ORDER _LITTLE_ENDIAN
#include <sys/endian.h>

#define	__STRICT_ALIGNMENT

#endif /* !_SH_ENDIAN_H_ */
