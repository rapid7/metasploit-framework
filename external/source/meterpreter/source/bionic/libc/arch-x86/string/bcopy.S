/*	$OpenBSD: bcopy.S,v 1.5 2005/08/07 11:30:38 espie Exp $	*/

/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from locore.s.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
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
 */

#include <machine/asm.h>

	/*
	 * (ov)bcopy (src,dst,cnt)
	 *  ws@tools.de     (Wolfgang Solfrank, TooLs GmbH) +49-228-985800
	 */

#ifdef MEMCOPY
ENTRY(memcpy)
#else
#ifdef MEMMOVE
ENTRY(memmove)
#else
ENTRY(bcopy)
#endif
#endif
	pushl	%esi
	pushl	%edi
#if defined(MEMCOPY) || defined(MEMMOVE)
	movl	12(%esp),%edi
	movl	16(%esp),%esi
	movl	%edi, %eax
#else
	movl	12(%esp),%esi
	movl	16(%esp),%edi
#endif
	movl	20(%esp),%ecx
	movl	%ecx,%edx
	cmpl	%esi,%edi	/* potentially overlapping? */
	jnb	1f
	cld			/* nope, copy forwards. */
	shrl	$2,%ecx		/* copy by words */
	rep
	movsl
	movl	%edx,%ecx
	andl	$3,%ecx		/* any bytes left? */
	rep
	movsb
	popl	%edi
	popl	%esi
	ret
1:
	addl	%ecx,%edi	/* copy backwards. */
	addl	%ecx,%esi
	std
	andl	$3,%ecx		/* any fractional bytes? */
	decl	%edi
	decl	%esi
	rep
	movsb
	movl	%edx,%ecx
	shrl	$2,%ecx
	subl	$3,%esi
	subl	$3,%edi
	rep
	movsl
	popl	%edi
	popl	%esi
	cld
	ret
