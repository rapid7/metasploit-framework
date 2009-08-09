/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
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
 *	@(#)SYS.h	5.5 (Berkeley) 5/7/91
 * $FreeBSD: head/lib/libc/i386/SYS.h 184548 2008-11-02 01:28:47Z peter $
 */

#include <sys/syscall.h>
#include <machine/asm.h>

#define	SYSCALL(x)	2: PIC_PROLOGUE; jmp PIC_PLT(HIDENAME(cerror));	\
			ENTRY(__CONCAT(__sys_,x));			\
			.weak CNAME(x);					\
			.set CNAME(x),CNAME(__CONCAT(__sys_,x));	\
			.weak CNAME(__CONCAT(_,x));			\
			.set CNAME(__CONCAT(_,x)),CNAME(__CONCAT(__sys_,x)); \
			mov __CONCAT($SYS_,x),%eax; KERNCALL; jb 2b

#define	RSYSCALL(x)	SYSCALL(x); ret; END(__CONCAT(__sys_,x))

#define	PSEUDO(x)	2: PIC_PROLOGUE; jmp PIC_PLT(HIDENAME(cerror)); \
			ENTRY(__CONCAT(__sys_,x));			\
			.weak CNAME(__CONCAT(_,x));			\
			.set CNAME(__CONCAT(_,x)),CNAME(__CONCAT(__sys_,x)); \
			mov __CONCAT($SYS_,x),%eax; KERNCALL; jb 2b; ret; \
			END(__CONCAT(__sys_,x))

/* gas messes up offset -- although we don't currently need it, do for BCS */
#define	LCALL(x,y)	.byte 0x9a ; .long y; .word x

#define KERNCALL	int $0x80
