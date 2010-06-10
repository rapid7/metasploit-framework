/*-
 * Copyright (c) 1993 The Regents of the University of California.
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
 * $FreeBSD: head/sys/i386/include/sysarch.h 145034 2005-04-13 22:57:17Z peter $
 */

/*
 * Architecture specific syscalls (i386)
 */
#ifndef _MACHINE_SYSARCH_H_
#define _MACHINE_SYSARCH_H_

#define I386_GET_LDT	0
#define I386_SET_LDT	1
#define	LDT_AUTO_ALLOC	0xffffffff
				/* I386_IOPL */
#define I386_GET_IOPERM	3
#define I386_SET_IOPERM	4
				/* xxxxx */
#define I386_VM86	6
#define I386_GET_FSBASE	7
#define I386_SET_FSBASE	8
#define I386_GET_GSBASE	9
#define I386_SET_GSBASE	10

/* These four only exist when running an i386 binary on amd64 */
#define	_AMD64_GET_FSBASE	128
#define	_AMD64_SET_FSBASE	129
#define	_AMD64_GET_GSBASE	130
#define	_AMD64_SET_GSBASE	131

struct i386_ldt_args {
	unsigned int start;
	union	descriptor *descs;
	unsigned int num;
}; 

struct i386_ioperm_args {
	unsigned int start;
	unsigned int length;
	int	enable;
};

struct i386_vm86_args {
	int	sub_op;			/* sub-operation to perform */
	char	*sub_args;		/* args */
};

#ifndef _KERNEL
#include <sys/cdefs.h>

union descriptor;
struct dbreg;

__BEGIN_DECLS
/* These four only exist when running an i386 binary on amd64 */
int _amd64_get_fsbase(void **);
int _amd64_get_gsbase(void **);
int _amd64_set_fsbase(void *);
int _amd64_set_gsbase(void *);
int i386_get_ldt(int, union descriptor *, int);
int i386_set_ldt(int, union descriptor *, int);
int i386_get_ioperm(unsigned int, unsigned int *, int *);
int i386_set_ioperm(unsigned int, unsigned int, int);
int i386_vm86(int, void *);
int i386_get_fsbase(void **);
int i386_get_gsbase(void **);
int i386_set_fsbase(void *);
int i386_set_gsbase(void *);
int i386_set_watch(int, unsigned int, int, int, struct dbreg *);
int i386_clr_watch(int, struct dbreg *);
int sysarch(int, void *);
__END_DECLS
#else
struct thread;
union descriptor;

int i386_get_ldt(struct thread *, struct i386_ldt_args *);
int i386_set_ldt(struct thread *, struct i386_ldt_args *, union descriptor *);
int i386_get_ioperm(struct thread *, struct i386_ioperm_args *);
int i386_set_ioperm(struct thread *, struct i386_ioperm_args *);
#endif

#endif /* !_MACHINE_SYSARCH_H_ */
