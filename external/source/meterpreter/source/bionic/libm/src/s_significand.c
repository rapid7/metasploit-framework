/* @(#)s_signif.c 5.1 93/09/24 */
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

#ifndef lint
static char rcsid[] = "$FreeBSD: src/lib/msun/src/s_significand.c,v 1.9 2003/07/23 04:53:47 peter Exp $";
#endif

/*
 * significand(x) computes just
 * 	scalb(x, (double) -ilogb(x)),
 * for exercising the fraction-part(F) IEEE 754-1985 test vector.
 */

#include "math.h"
#include "math_private.h"

double
significand(double x)
{
	return __ieee754_scalb(x,(double) -ilogb(x));
}
