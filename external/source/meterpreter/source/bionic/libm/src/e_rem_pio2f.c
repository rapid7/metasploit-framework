/* e_rem_pio2f.c -- float version of e_rem_pio2.c
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
static char rcsid[] = "$FreeBSD: src/lib/msun/src/e_rem_pio2f.c,v 1.19 2005/11/23 03:03:09 bde Exp $";
#endif

/* __ieee754_rem_pio2f(x,y)
 *
 * return the remainder of x rem pi/2 in y[0]+y[1]
 * use double precision internally
 * use __kernel_rem_pio2() for large x
 */

#include "math.h"
#include "math_private.h"

/*
 * Table of constants for 2/pi, 396 Hex digits (476 decimal) of 2/pi
 */
static const int32_t two_over_pi[] = {
0xA2F983, 0x6E4E44, 0x1529FC, 0x2757D1, 0xF534DD, 0xC0DB62, 
0x95993C, 0x439041, 0xFE5163, 0xABDEBB, 0xC561B7, 0x246E3A, 
0x424DD2, 0xE00649, 0x2EEA09, 0xD1921C, 0xFE1DEB, 0x1CB129, 
0xA73EE8, 0x8235F5, 0x2EBB44, 0x84E99C, 0x7026B4, 0x5F7E41, 
0x3991D6, 0x398353, 0x39F49C, 0x845F8B, 0xBDF928, 0x3B1FF8, 
0x97FFDE, 0x05980F, 0xEF2F11, 0x8B5A0A, 0x6D1F6D, 0x367ECF, 
0x27CB09, 0xB74F46, 0x3F669E, 0x5FEA2D, 0x7527BA, 0xC7EBE5, 
0xF17B3D, 0x0739F7, 0x8A5292, 0xEA6BFB, 0x5FB11F, 0x8D5D08, 
0x560330, 0x46FC7B, 0x6BABF0, 0xCFBC20, 0x9AF436, 0x1DA9E3, 
0x91615E, 0xE61B08, 0x659985, 0x5F14A0, 0x68408D, 0xFFD880, 
0x4D7327, 0x310606, 0x1556CA, 0x73A8C9, 0x60E27B, 0xC08C6B, 
};

/*
 * invpio2:  53 bits of 2/pi
 * pio2_1:   first  33 bit of pi/2
 * pio2_1t:  pi/2 - pio2_1
 */

static const double
zero =  0.00000000000000000000e+00, /* 0x00000000, 0x00000000 */
half =  5.00000000000000000000e-01, /* 0x3FE00000, 0x00000000 */
two24 =  1.67772160000000000000e+07, /* 0x41700000, 0x00000000 */
invpio2 =  6.36619772367581382433e-01, /* 0x3FE45F30, 0x6DC9C883 */
pio2_1  =  1.57079632673412561417e+00, /* 0x3FF921FB, 0x54400000 */
pio2_1t =  6.07710050650619224932e-11; /* 0x3DD0B461, 0x1A626331 */

	int32_t __ieee754_rem_pio2f(float x, float *y)
{
	double w,t,r,fn;
	double tx[1],ty[2];
	float z;
	int32_t e0,n,ix,hx;

	GET_FLOAT_WORD(hx,x);
	ix = hx&0x7fffffff;
    /* 33+53 bit pi is good enough for medium size */
	if(ix<=0x49490f80) {		/* |x| ~<= 2^19*(pi/2), medium size */
	    t  = fabsf(x);
	    n  = (int32_t) (t*invpio2+half);
	    fn = (double)n;
	    r  = t-fn*pio2_1;
	    w  = fn*pio2_1t;
	    y[0] = r-w;
	    y[1] = (r-y[0])-w;
	    if(hx<0) 	{y[0] = -y[0]; y[1] = -y[1]; return -n;}
	    else	 return n;
	}
    /*
     * all other (large) arguments
     */
	if(ix>=0x7f800000) {		/* x is inf or NaN */
	    y[0]=y[1]=x-x; return 0;
	}
    /* set z = scalbn(|x|,ilogb(|x|)-23) */
	e0 = (ix>>23)-150;		/* e0 = ilogb(|x|)-23; */
	SET_FLOAT_WORD(z, ix - ((int32_t)(e0<<23)));
	tx[0] = z;
	n  =  __kernel_rem_pio2(tx,ty,e0,1,1,two_over_pi);
	y[0] = ty[0];
	y[1] = ty[0] - y[0];
	if(hx<0) {y[0] = -y[0]; y[1] = -y[1]; return -n;}
	return n;
}
