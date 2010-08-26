/*-
 * Copyright (c) 2004-2005 David Schultz <das@FreeBSD.ORG>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/lib/msun/ia64/fenv.h,v 1.4 2005/03/16 19:03:45 das Exp $
 */

#ifndef	_FENV_H_
#define	_FENV_H_

#include <sys/_types.h>

typedef	__uint64_t	fenv_t;
typedef	__uint16_t	fexcept_t;

/* Exception flags */
#define	FE_INVALID	0x01
#define	FE_DENORMAL	0x02
#define	FE_DIVBYZERO	0x04
#define	FE_OVERFLOW	0x08
#define	FE_UNDERFLOW	0x10
#define	FE_INEXACT	0x20
#define	FE_ALL_EXCEPT	(FE_DIVBYZERO | FE_DENORMAL | FE_INEXACT | \
			 FE_INVALID | FE_OVERFLOW | FE_UNDERFLOW)

/* Rounding modes */
#define	FE_TONEAREST	0x0000
#define	FE_DOWNWARD	0x0400
#define	FE_UPWARD	0x0800
#define	FE_TOWARDZERO	0x0c00
#define	_ROUND_MASK	(FE_TONEAREST | FE_DOWNWARD | \
			 FE_UPWARD | FE_TOWARDZERO)

__BEGIN_DECLS

/* Default floating-point environment */
extern const fenv_t	__fe_dfl_env;
#define	FE_DFL_ENV	(&__fe_dfl_env)

#define	_FPUSW_SHIFT	13

#define	__stfpsr(__r)	__asm __volatile("mov %0=ar.fpsr" : "=r" (*(__r)))
#define	__ldfpsr(__r)	__asm __volatile("mov ar.fpsr=%0;;" : : "r" (__r))

static __inline int
feclearexcept(int __excepts)
{
	fenv_t __fpsr;

	__stfpsr(&__fpsr);
	__fpsr &= ~((fenv_t)__excepts << _FPUSW_SHIFT);
	__ldfpsr(__fpsr);
	return (0);
}

static __inline int
fegetexceptflag(fexcept_t *__flagp, int __excepts)
{
	fenv_t __fpsr;

	__stfpsr(&__fpsr);
	*__flagp = (fexcept_t)(__fpsr >> _FPUSW_SHIFT) & __excepts;
	return (0);
}

static __inline int
fesetexceptflag(const fexcept_t *__flagp, int __excepts)
{
	fenv_t __fpsr;

	__stfpsr(&__fpsr);
	__fpsr &= ~((fenv_t)__excepts << _FPUSW_SHIFT);
	__fpsr |= (fenv_t)(__excepts & *__flagp) << _FPUSW_SHIFT;
	__ldfpsr(__fpsr);
	return (0);
}

/*
 * It is worthwhile to use the inline version of this function iff it
 * is called with arguments that are compile-time constants (due to
 * dead code elimination).  Unfortunately, gcc isn't smart enough to
 * figure this out automatically, and there's no way to tell it.
 * We assume that constant arguments will be the common case.
 */
static __inline int
feraiseexcept(int __excepts)
{
	volatile double d;

	/*
	 * With a compiler that supports the FENV_ACCESS pragma
	 * properly, simple expressions like '0.0 / 0.0' should
	 * be sufficient to generate traps.  Unfortunately, we
	 * need to bring a volatile variable into the equation
	 * to prevent incorrect optimizations.
	 */
	if (__excepts & FE_INVALID) {
		d = 0.0;
		d = 0.0 / d;
	}
	if (__excepts & FE_DIVBYZERO) {
		d = 0.0;
		d = 1.0 / d;
	}
	if (__excepts & FE_OVERFLOW) {
		d = 0x1.ffp1023;
		d *= 2.0;
	}
	if (__excepts & FE_UNDERFLOW) {
		d = 0x1p-1022;
		d /= 0x1p1023;
	}
	if (__excepts & FE_INEXACT) {
		d = 0x1p-1022;
		d += 1.0;
	}
	return (0);
}

static __inline int
fetestexcept(int __excepts)
{
	fenv_t __fpsr;

	__stfpsr(&__fpsr);
	return ((__fpsr >> _FPUSW_SHIFT) & __excepts);
}


static __inline int
fegetround(void)
{
	fenv_t __fpsr;

	__stfpsr(&__fpsr);
	return (__fpsr & _ROUND_MASK);
}

static __inline int
fesetround(int __round)
{
	fenv_t __fpsr;

	if (__round & ~_ROUND_MASK)
		return (-1);
	__stfpsr(&__fpsr);
	__fpsr &= ~_ROUND_MASK;
	__fpsr |= __round;
	__ldfpsr(__fpsr);
	return (0);
}

static __inline int
fegetenv(fenv_t *__envp)
{

	__stfpsr(__envp);
	return (0);
}

static __inline int
feholdexcept(fenv_t *__envp)
{
	fenv_t __fpsr;

	__stfpsr(&__fpsr);
	*__envp = __fpsr;
	__fpsr &= ~((fenv_t)FE_ALL_EXCEPT << _FPUSW_SHIFT);
	__fpsr |= FE_ALL_EXCEPT;
	__ldfpsr(__fpsr);
	return (0);
}

static __inline int
fesetenv(const fenv_t *__envp)
{

	__ldfpsr(*__envp);
	return (0);
}

int feupdateenv(const fenv_t *__envp);

#if __BSD_VISIBLE

static __inline int
feenableexcept(int __mask)
{
	fenv_t __newfpsr, __oldfpsr;

	__stfpsr(&__oldfpsr);
	__newfpsr = __oldfpsr & ~(__mask & FE_ALL_EXCEPT);
	__ldfpsr(__newfpsr);
	return (~__oldfpsr & FE_ALL_EXCEPT);
}

static __inline int
fedisableexcept(int __mask)
{
	fenv_t __newfpsr, __oldfpsr;

	__stfpsr(&__oldfpsr);
	__newfpsr = __oldfpsr | (__mask & FE_ALL_EXCEPT);
	__ldfpsr(__newfpsr);
	return (~__oldfpsr & FE_ALL_EXCEPT);
}

static __inline int
fegetexcept(void)
{
	fenv_t __fpsr;

	__stfpsr(&__fpsr);
	return (~__fpsr & FE_ALL_EXCEPT);
}

#endif /* __BSD_VISIBLE */

__END_DECLS

#endif	/* !_FENV_H_ */
