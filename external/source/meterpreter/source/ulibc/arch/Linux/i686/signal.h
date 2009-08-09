/*-
 * Copyright (c) 1986, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)signal.h	8.1 (Berkeley) 6/11/93
 * $FreeBSD: head/sys/i386/include/signal.h 190623 2009-04-01 13:44:28Z kib $
 */

#ifndef _MACHINE_SIGNAL_H_
#define	_MACHINE_SIGNAL_H_

#include <sys/cdefs.h>
#include <sys/_sigset.h>

/*
 * Machine-dependent signal definitions
 */

typedef int sig_atomic_t;

#if __BSD_VISIBLE
#include <machine/trap.h>	/* codes for SIGILL, SIGFPE */

/*
 * Only the kernel should need these old type definitions.
 */
#if defined(_KERNEL) && defined(COMPAT_43)
/*
 * Information pushed on stack when a signal is delivered.
 * This is used by the kernel to restore state following
 * execution of the signal handler.  It is also made available
 * to the handler to allow it to restore state properly if
 * a non-standard exit is performed.
 */
struct osigcontext {
	int	sc_onstack;		/* sigstack state to restore */
	osigset_t sc_mask;		/* signal mask to restore */
	int	sc_esp;			/* machine state follows: */
	int	sc_ebp;
	int	sc_isp;
	int	sc_eip;
	int	sc_efl;
	int	sc_es;
	int	sc_ds;
	int	sc_cs;
	int	sc_ss;
	int	sc_edi;
	int	sc_esi;
	int	sc_ebx;
	int	sc_edx;
	int	sc_ecx;
	int	sc_eax;
	int	sc_gs;
	int	sc_fs;
	int	sc_trapno;
	int	sc_err;
};
#endif

/*
 * The sequence of the fields/registers in struct sigcontext should match
 * those in mcontext_t.
 */
struct sigcontext {
	struct __sigset sc_mask;	/* signal mask to restore */
	int	sc_onstack;		/* sigstack state to restore */
	int	sc_gs;			/* machine state (struct trapframe) */
	int	sc_fs;
	int	sc_es;
	int	sc_ds;
	int	sc_edi;
	int	sc_esi;
	int	sc_ebp;
	int	sc_isp;
	int	sc_ebx;
	int	sc_edx;
	int	sc_ecx;
	int	sc_eax;
	int	sc_trapno;
	int	sc_err;
	int	sc_eip;
	int	sc_cs;
	int	sc_efl;
	int	sc_esp;
	int	sc_ss;
	int	sc_len;			/* sizeof(mcontext_t) */
	/*
	 * XXX - See <machine/ucontext.h> and <machine/npx.h> for
	 *       the following fields.
	 */
	int	sc_fpformat;
	int	sc_ownedfp;
	int	sc_spare1[1];
	int	sc_fpstate[128] __aligned(16);

	int	sc_fsbase;
	int	sc_gsbase;

	int	sc_spare2[6];
};

#define	sc_sp		sc_esp
#define	sc_fp		sc_ebp
#define	sc_pc		sc_eip
#define	sc_ps		sc_efl
#define	sc_eflags	sc_efl

#endif /* __BSD_VISIBLE */

#endif /* !_MACHINE_SIGNAL_H_ */
