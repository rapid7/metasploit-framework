/* s_cbrtf.c -- float version of s_cbrt.c.
 * Conversion to float by Ian Lance Taylor, Cygnus Support, ian@cygnus.com.
 * Debugged and optimized by Bruce D. Evans.
 */

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
static char rcsid[] = "$FreeBSD: src/lib/msun/src/s_cbrtf.c,v 1.12 2005/12/13 20:17:23 bde Exp $";
#endif

#include "math.h"
#include "math_private.h"

/* cbrtf(x)
 * Return cube root of x
 */
static const unsigned
	B1 = 709958130, /* B1 = (127-127.0/3-0.03306235651)*2**23 */
	B2 = 642849266; /* B2 = (127-127.0/3-24/3-0.03306235651)*2**23 */

static const float
C =  5.4285717010e-01, /* 19/35     = 0x3f0af8b0 */
D = -7.0530611277e-01, /* -864/1225 = 0xbf348ef1 */
E =  1.4142856598e+00, /* 99/70     = 0x3fb50750 */
F =  1.6071428061e+00, /* 45/28     = 0x3fcdb6db */
G =  3.5714286566e-01; /* 5/14      = 0x3eb6db6e */

float
cbrtf(float x)
{
	float r,s,t,w;
	int32_t hx;
	u_int32_t sign;
	u_int32_t high;

	GET_FLOAT_WORD(hx,x);
	sign=hx&0x80000000; 		/* sign= sign(x) */
	hx  ^=sign;
	if(hx>=0x7f800000) return(x+x); /* cbrt(NaN,INF) is itself */
	if(hx==0)
	    return(x);		/* cbrt(0) is itself */

    /* rough cbrt to 5 bits */
	if(hx<0x00800000) { 		/* subnormal number */
	    SET_FLOAT_WORD(t,0x4b800000); /* set t= 2**24 */
	    t*=x;
	    GET_FLOAT_WORD(high,t);
	    SET_FLOAT_WORD(t,sign|((high&0x7fffffff)/3+B2));
	} else
	    SET_FLOAT_WORD(t,sign|(hx/3+B1));

    /* new cbrt to 23 bits */
	r=t*t/x;
	s=C+r*t;
	t*=G+F/(s+E+D/s);

    /* chop t to 12 bits and make it larger in magnitude than cbrt(x) */
	GET_FLOAT_WORD(high,t);
	SET_FLOAT_WORD(t,(high&0xfffff000)+0x00001000);

    /* one step Newton iteration to 24 bits with error less than 0.667 ulps */
	s=t*t;		/* t*t is exact */
	r=x/s;
	w=t+t;
	r=(r-t)/(w+r);	/* r-t is exact */
	t=t+t*r;

	return(t);
}
