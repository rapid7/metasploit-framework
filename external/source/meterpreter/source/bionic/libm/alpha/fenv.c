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
 * $FreeBSD: src/lib/msun/alpha/fenv.c,v 1.2 2005/03/16 19:03:44 das Exp $
 */

#include <sys/cdefs.h>
#include <machine/sysarch.h>
#include <fenv.h>

const fenv_t __fe_dfl_env = 0x680e000000000000ULL;

struct mask_args {
	fenv_t mask;
};

/*
 * The lower 49 bits of the FPCR are unused by the hardware, so we use
 * the lower order bits to store the kernel's idea of the FP mask as
 * described in the Alpha Architecture Manual.
 */
int
fegetenv(fenv_t *envp)
{
	struct mask_args p;
	union __fpcr r;

	/*
	 * The syscall acts as an implicit exception barrier, so we
	 * only need to issue an excb after the mf_fpcr to ensure that
	 * the read is executed before any subsequent FP ops.
	 */
	sysarch(ALPHA_GET_FPMASK, (char *)&p);
	__mf_fpcr(&r.__d);
	*envp = r.__bits | p.mask;
	__excb();
	return (0);
}

int
feholdexcept(fenv_t *envp)
{
	struct mask_args p;
	union __fpcr r;

	sysarch(ALPHA_GET_FPMASK, (char *)&p);
	__mf_fpcr(&r.__d);
	*envp = r.__bits | p.mask;
	r.__bits &= ~((fenv_t)FE_ALL_EXCEPT << _FPUSW_SHIFT);
	__mt_fpcr(r.__d);
	if (p.mask & FE_ALL_EXCEPT) {
		p.mask = 0;
		sysarch(ALPHA_SET_FPMASK, &p);
	}
	__excb();
	return (0);
}

int
fesetenv(const fenv_t *envp)
{
	struct mask_args p;
	union __fpcr r;

	p.mask = *envp & FE_ALL_EXCEPT;
	sysarch(ALPHA_SET_FPMASK, &p);
	r.__bits = *envp & ~FE_ALL_EXCEPT;
	__mt_fpcr(r.__d);
	__excb();
	return (0);
}

int
feupdateenv(const fenv_t *envp)
{
	struct mask_args p;
	union __fpcr oldr, newr;

	p.mask = *envp & FE_ALL_EXCEPT;
	sysarch(ALPHA_SET_FPMASK, &p);
	__mf_fpcr(&oldr.__d);
	newr.__bits = *envp & ~FE_ALL_EXCEPT;
	__excb();
	__mt_fpcr(newr.__d);
	feraiseexcept((oldr.__bits >> _FPUSW_SHIFT) & FE_ALL_EXCEPT);
	return (0); 
}

int
__feenableexcept(int mask)
{
	struct mask_args p;

	sysarch(ALPHA_GET_FPMASK, &p);
	p.mask |= (mask & FE_ALL_EXCEPT);
	sysarch(ALPHA_SET_FPMASK, &p);
	return (p.mask);
}

int
__fedisableexcept(int mask)
{
	struct mask_args p;

	sysarch(ALPHA_GET_FPMASK, &p);
	p.mask &= ~(mask & FE_ALL_EXCEPT);
	sysarch(ALPHA_SET_FPMASK, &p);
	return (p.mask);
}

int
__fegetexcept(void)
{
	struct mask_args p;

	sysarch(ALPHA_GET_FPMASK, &p);
	return (p.mask);
}

__weak_reference(__feenableexcept, feenableexcept);
__weak_reference(__fedisableexcept, fedisableexcept);
__weak_reference(__fegetexcept, fegetexcept);
