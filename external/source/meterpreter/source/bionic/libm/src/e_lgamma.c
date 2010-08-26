
/* @(#)e_lgamma.c 1.3 95/01/18 */
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunSoft, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice 
 * is preserved.
 * ====================================================
 *
 */

#ifndef lint
static char rcsid[] = "$FreeBSD: src/lib/msun/src/e_lgamma.c,v 1.8 2005/02/04 18:26:06 das Exp $";
#endif

/* __ieee754_lgamma(x)
 * Return the logarithm of the Gamma function of x.
 *
 * Method: call __ieee754_lgamma_r
 */

#include "math.h"
#include "math_private.h"

extern int signgam;

double
__ieee754_lgamma(double x)
{
	return __ieee754_lgamma_r(x,&signgam);
}
