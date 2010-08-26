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
 * $FreeBSD: src/lib/msun/alpha/fenv.h,v 1.3 2005/03/16 19:03:44 das Exp $
 */

#ifndef	_FENV_H_
#define	_FENV_H_

#include <sys/_types.h>

typedef	__uint64_t	fenv_t;
typedef	__uint16_t	fexcept_t;

/* Exception flags */
#define	FE_INVALID	0x02
#define	FE_DIVBYZERO	0x04
#define	FE_OVERFLOW	0x08
#define	FE_UNDERFLOW	0x10
#define	FE_INEXACT	0x20
#define	FE_INTOVF	0x40	/* not maskable */
#define	FE_ALL_EXCEPT	(FE_DIVBYZERO | FE_INEXACT | FE_INTOVF | \
			 FE_INVALID | FE_OVERFLOW | FE_UNDERFLOW)

/* Rounding modes */
#define	FE_TOWARDZERO	0x00
#define	FE_DOWNWARD	0x01
#define	FE_TONEAREST	0x02
#define	FE_UPWARD	0x03
#define	_ROUND_MASK	(FE_TONEAREST | FE_DOWNWARD | \
			 FE_UPWARD | FE_TOWARDZERO)
#define	_ROUND_SHIFT	58

#define	_FPUSW_SHIFT	51

#define	__excb()	__asm __volatile("excb")
#define	__mf_fpcr(__cw)	__asm __volatile("mf_fpcr %0" : "=f" (*(__cw)))
#define	__mt_fpcr(__cw)	__asm __volatile("mt_fpcr %0" : : "f" (__cw))

union __fpcr {
	double __d;
	fenv_t __bits;
};

__BEGIN_DECLS

/* Default floating-point environment */
extern const fenv_t	__fe_dfl_env;
#define	FE_DFL_ENV	(&__fe_dfl_env)

static __inline int
feclearexcept(int __excepts)
{
	union __fpcr __r;

	__excb();
	__mf_fpcr(&__r.__d);
	__r.__bits &= ~((fenv_t)__excepts << _FPUSW_SHIFT);
	__mt_fpcr(__r.__d);
	__excb();
	return (0);
}

static __inline int
fegetexceptflag(fexcept_t *__flagp, int __excepts)
{
	union __fpcr __r;

	__excb();
	__mf_fpcr(&__r.__d);
	__excb();
	*__flagp = (__r.__bits >> _FPUSW_SHIFT) & __excepts;
	return (0);
}

static __inline int
fesetexceptflag(const fexcept_t *__flagp, int __excepts)
{
	union __fpcr __r;
	fenv_t __xflag, __xexcepts;

	__xflag = (fenv_t)*__flagp << _FPUSW_SHIFT;
	__xexcepts = (fenv_t)__excepts << _FPUSW_SHIFT;
	__excb();
	__mf_fpcr(&__r.__d);
	__r.__bits &= ~__xexcepts;
	__r.__bits |= __xflag & __xexcepts;
	__mt_fpcr(__r.__d);
	__excb();
	return (0);
}

static __inline int
feraiseexcept(int __excepts)
{

	/*
	 * XXX Generating exceptions this way does not actually invoke
	 * a userland trap handler when enabled, but neither do
	 * arithmetic operations as far as I can tell.  Perhaps there
	 * are more bugs in the kernel trap handler.
	 */
	fexcept_t __ex = __excepts;
	fesetexceptflag(&__ex, __excepts);
	return (0);
}

static __inline int
fetestexcept(int __excepts)
{
	union __fpcr __r;

	__excb();
	__mf_fpcr(&__r.__d);
	__excb();
	return ((__r.__bits >> _FPUSW_SHIFT) & __excepts);
}

static __inline int
fegetround(void)
{
	union __fpcr __r;

	/*
	 * No exception barriers should be required here if we assume
	 * that only fesetround() can change the rounding mode.
	 */
	__mf_fpcr(&__r.__d);
	return ((int)(__r.__bits >> _ROUND_SHIFT) & _ROUND_MASK);
}

static __inline int
fesetround(int __round)
{
	union __fpcr __r;

	if (__round & ~_ROUND_MASK)
		return (-1);
	__excb();
	__mf_fpcr(&__r.__d);
	__r.__bits &= ~((fenv_t)_ROUND_MASK << _ROUND_SHIFT);
	__r.__bits |= (fenv_t)__round << _ROUND_SHIFT;
	__mt_fpcr(__r.__d);
	__excb();
	return (0);
}

int	fegetenv(fenv_t *__envp);
int	feholdexcept(fenv_t *__envp);
int	fesetenv(const fenv_t *__envp);
int	feupdateenv(const fenv_t *__envp);

#if __BSD_VISIBLE

int	feenableexcept(int __mask);
int	fedisableexcept(int __mask);
int	fegetexcept(void);

#endif /* __BSD_VISIBLE */

__END_DECLS

#endif	/* !_FENV_H_ */
