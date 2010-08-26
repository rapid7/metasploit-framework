/*
 * Copyright (C) 2009 Android Open Source Project, All rights reserved.
 *   Derived from "bionic/libm/arm/fenv.h"
 *   Copyright (c) 2004-2005 David Schultz <das@FreeBSD.ORG>
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

#ifndef _FENV_H_
#define _FENV_H_

#include <stdio.h>
#include <sys/types.h>

typedef	uint32_t	fenv_t;
typedef	uint32_t	fexcept_t;

/* Exception flags */
#define	FE_INVALID		0x0010
#define	FE_DIVBYZERO	0x0008
#define	FE_OVERFLOW		0x0004
#define	FE_UNDERFLOW	0x0002
#define	FE_INEXACT		0x0001
#define	FE_ALL_EXCEPT	(FE_DIVBYZERO | FE_INEXACT | \
				 FE_INVALID | FE_OVERFLOW | FE_UNDERFLOW)

/* Rounding modes */
#define	FE_TONEAREST	0x0000
#define	FE_TOWARDZERO	0x0001
#define	FE_UPWARD	0x0002 /* not supporetd */
#define	FE_DOWNWARD	0x0003 /* not supporetd */
#define	_ROUND_MASK	(FE_TONEAREST | FE_DOWNWARD | \
				 FE_UPWARD | FE_TOWARDZERO)

/* bit shift for FPSCR mapping */
#define	_FPUE_CAUSE_SHIFT	12
#define	_FPUE_ENABLE_SHIFT	17
#define	_FPUE_FLAG_SHIFT	 2

/* bit shifters */
#define	_FPUE_CAUSE(_EXCS)	((_EXCS) << _FPUE_CAUSE_SHIFT)
#define	_FPUE_ENABLE(_EXCS)	((_EXCS) << _FPUE_ENABLE_SHIFT)
#define	_FPUE_FLAG(_EXCS)	((_EXCS) << _FPUE_FLAG_SHIFT)

#define	_GET_FPUE_CAUSE(_FPUE)		(((_FPUE) >> _FPUE_CAUSE_SHIFT) & FE_ALL_EXCEPT)
#define	_GET_FPUE_ENABLE(_FPUE)	(((_FPUE) >> _FPUE_ENABLE_SHIFT)& FE_ALL_EXCEPT)
#define	_GET_FPUE_FLAG(_FPUE)		(((_FPUE) >> _FPUE_FLAG_SHIFT) & FE_ALL_EXCEPT)


/* FPSCR register accessors */
#ifdef	__SH4_NOFPU__
#define	__read_fpscr(_ptr)
#define	__write_fpscr(_val)
#else
#define	__read_fpscr(_ptr)	__asm __volatile("sts fpscr, %0" : "=r" (*(_ptr)))
#define	__write_fpscr(_val)	__asm __volatile("lds %0, fpscr" : : "r" (_val))
#endif


/* functions for libm */
static __inline int
feclearexcept(int __excepts)
{
	uint32_t __fpscr;

	__read_fpscr(&__fpscr);
	__fpscr &= ~_FPUE_FLAG(__excepts);
	__write_fpscr(__fpscr);
	return (0);
}

static __inline int
fegetexceptflag(fexcept_t *__flagp, int __excepts)
{
	uint32_t __fpscr;

	__read_fpscr(&__fpscr);
	*__flagp = _GET_FPUE_FLAG(__fpscr) & __excepts;
	return (0);
}


static __inline int
fesetexceptflag(const fexcept_t *__flagp, int __excepts)
{
	uint32_t __fpscr;

	__read_fpscr(&__fpscr);
	__fpscr &= ~_FPUE_FLAG(__excepts);
	__fpscr |= ~_FPUE_FLAG(*__flagp & __excepts);
	__write_fpscr(__fpscr);
	return (0);
}


static __inline int
feraiseexcept(int __excepts)
{
	fexcept_t __ex = __excepts;

	fesetexceptflag(&__ex, __excepts);	/* XXX */
	return (0);
}


static __inline int
fetestexcept(int __excepts)
{
	fexcept_t __ex;

	fegetexceptflag(&__ex,  __excepts);
	return (__ex);
}


static __inline int
fegetround(void)
{
	uint32_t __fpscr = 0;

	__read_fpscr(&__fpscr);
	return (__fpscr & _ROUND_MASK);	
}

static __inline int
fesetround(int __round)
{
	uint32_t __fpscr = 0;

	if (__round == FE_UPWARD || __round == FE_DOWNWARD) {
		fprintf(stderr, "libm superh : "
			"upward/downward rounding not supporetd.\n");
		return -1;
	}

	__read_fpscr(&__fpscr);
	__fpscr &= ~_ROUND_MASK;
	__fpscr |= (__round & _ROUND_MASK);
	__write_fpscr(__fpscr);
	return (0);
}

static __inline int
fegetenv(fenv_t *__envp)
{
	__read_fpscr(__envp);
	return (0);
}

static __inline int
feholdexcept(fenv_t *__envp)
{
	uint32_t __fpscr;

	__read_fpscr(&__fpscr);
	*__envp = __fpscr;
	__fpscr &= ~_FPUE_FLAG(FE_ALL_EXCEPT);
	__write_fpscr(__fpscr);
	return (0);
}


static __inline int
fesetenv(const fenv_t *__envp)
{
	__write_fpscr(*__envp);
	return (0);
}


static __inline int
feupdateenv(const fenv_t *__envp)
{
	uint32_t __fpscr;

	__read_fpscr(&__fpscr);
	__write_fpscr(*__envp);
	feraiseexcept(_GET_FPUE_FLAG(__fpscr));
	return (0);
}

#if __BSD_VISIBLE

static __inline int
feenableexcept(int __mask)
{
	uint32_t __old_fpscr, __new_fpscr;

	__read_fpscr(&__old_fpscr);
	__new_fpscr = __old_fpscr | _FPUE_ENABLE(__mask & FE_ALL_EXCEPT);
	__write_fpscr(__new_fpscr);
	return (_GET_FPUE_ENABLE(__old_fpscr));
}

static __inline int
fedisableexcept(int __mask)
{
	uint32_t __old_fpscr, __new_fpscr;

	__read_fpscr(&__old_fpscr);
	__new_fpscr = __old_fpscr & ~(_FPUE_ENABLE(__mask & FE_ALL_EXCEPT));
	__write_fpscr(__new_fpscr);
	return (_GET_FPUE_ENABLE(__old_fpscr));
}

static __inline int
fegetexcept(void)
{
	uint32_t __fpscr;

	__read_fpscr(&__fpscr);
	return (_GET_FPUE_ENABLE(__fpscr));
}

#endif /* __BSD_VISIBLE */


#endif /* _FENV_H_ */

