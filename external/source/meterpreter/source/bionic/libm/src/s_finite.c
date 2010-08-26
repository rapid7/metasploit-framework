/* @(#)s_finite.c 5.1 93/09/24 */
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
static char rcsid[] = "$FreeBSD: src/lib/msun/src/s_finite.c,v 1.8 2003/07/23 04:53:46 peter Exp $";
#endif

/*
 * finite(x) returns 1 is x is finite, else 0;
 * no branching!
 */

#include "math.h"
#include "math_private.h"

	int finite(double x)
{
	int32_t hx;
	GET_HIGH_WORD(hx,x);
	return (int)((u_int32_t)((hx&0x7fffffff)-0x7ff00000)>>31);
}
