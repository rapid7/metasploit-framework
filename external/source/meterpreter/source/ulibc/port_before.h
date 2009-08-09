/* $FreeBSD: user/kmacy/releng_7_2_zfs/lib/libc/include/port_before.h 156956 2006-03-21 15:37:16Z ume $ */

#ifndef _PORT_BEFORE_H_
#define _PORT_BEFORE_H_

#define _LIBC		1
#define DO_PTHREADS	1
#define USE_KQUEUE	1

#define ISC_SOCKLEN_T	socklen_t
#define ISC_FORMAT_PRINTF(fmt, args) \
	__attribute__((__format__(__printf__, fmt, args)))
#define DE_CONST(konst, var) \
        do { \
                union { const void *k; void *v; } _u; \
                _u.k = konst; \
                var = _u.v; \
        } while (0)

#define UNUSED(x) (x) = (x)

#endif /* _PORT_BEFORE_H_ */
