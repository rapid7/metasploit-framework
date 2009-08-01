/*-
 * Copyright 1996-1998 John D. Polstra.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: head/libexec/rtld-elf/amd64/rtld_start.S 127254 2004-03-21 01:43:39Z peter $
 */

	.text
	.align	4
	.globl	.rtld_start
	.type	.rtld_start,@function
.rtld_start:
	xorq	%rbp,%rbp		# Clear frame pointer for good form
	subq	$24,%rsp		# A place to store exit procedure addr
	movq	%rdi,%r12
	movq	%rsp,%rsi		# save address of exit proc
	movq	%rsp,%rdx		# construct address of obj_main
	addq	$8,%rdx
	call	_rtld_late@PLT		# Call rtld(sp); returns entry point
	popq	%rsi			# Get exit procedure address
	movq	%r12,%rdi		# *ap
/*
 * At this point, %rax contains the entry point of the main program, and
 * %rdx contains a pointer to a termination function that should be
 * registered with atexit().  (crt1.o registers it.)
 */
.globl .rtld_goto_main
.rtld_goto_main:	# This symbol exists just to make debugging easier.
	jmp	*%rax			# Enter main program


/*
 * Binder entry point.  Control is transferred to here by code in the PLT.
 * On entry, there are two arguments on the stack.  In ascending address
 * order, they are (1) "obj", a pointer to the calling object's Obj_Entry,
 * and (2) "reloff", the byte offset of the appropriate relocation entry
 * in the PLT relocation table.
 *
 * We are careful to preserve all registers, even the the caller-save
 * registers.  That is because this code may be invoked by low-level
 * assembly-language code that is not ABI-compliant.
 *
 * Stack map:
 * reloff       0x60
 * obj          0x58
 * spare	0x50
 * rflags       0x48
 * rax          0x40
 * rdx          0x38
 * rcx          0x30
 * rsi          0x28
 * rdi          0x20
 * r8           0x18
 * r9           0x10
 * r10          0x8
 * r11          0x0
 */
	.align	4
	.globl	_rtld_bind_start
	.type	_rtld_bind_start,@function
_rtld_bind_start:
	subq	$8,%rsp
	pushfq				# Save rflags
	pushq	%rax			# Save %rax
	pushq	%rdx			# Save %rdx
	pushq	%rcx			# Save %rcx
	pushq	%rsi			# Save %rsi
	pushq	%rdi			# Save %rdi
	pushq	%r8			# Save %r8
	pushq	%r9			# Save %r9
	pushq	%r10			# Save %r10
	pushq	%r11			# Save %r11

	movq	0x58(%rsp),%rdi		# Fetch obj argument
	movq	0x60(%rsp),%rsi		# Fetch reloff argument
	leaq	(%rsi,%rsi,2),%rsi	# multiply by 3
	leaq	(,%rsi,8),%rsi		# now 8, for 24 (sizeof Elf_Rela)

	call	_rtld_bind@PLT		# Transfer control to the binder
	/* Now %rax contains the entry point of the function being called. */

	movq	%rax,0x60(%rsp)		# Store target over reloff argument
	popq	%r11			# Restore %r11
	popq	%r10			# Restore %r10
	popq	%r9			# Restore %r9
	popq	%r8			# Restore %r8
	popq	%rdi			# Restore %rdi
	popq	%rsi			# Restore %rsi
	popq	%rcx			# Restore %rcx
	popq	%rdx			# Restore %rdx
	popq	%rax			# Restore %rax
	popfq				# Restore rflags
	leaq	16(%rsp),%rsp		# Discard spare, obj, do not change rflags
	ret				# "Return" to target address
