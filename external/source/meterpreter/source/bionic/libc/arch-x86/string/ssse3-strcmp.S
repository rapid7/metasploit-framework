/*
Copyright (c) 2010, Intel Corporation
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    * this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
    * this list of conditions and the following disclaimer in the documentation
    * and/or other materials provided with the distribution.

    * Neither the name of Intel Corporation nor the names of its contributors
    * may be used to endorse or promote products derived from this software
    * without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef L
# define L(label)	.L##label
#endif

#ifndef cfi_startproc
# define cfi_startproc			.cfi_startproc
#endif

#ifndef cfi_endproc
# define cfi_endproc			.cfi_endproc
#endif

#ifndef cfi_rel_offset
# define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
#endif

#ifndef cfi_restore
# define cfi_restore(reg)		.cfi_restore (reg)
#endif

#ifndef cfi_adjust_cfa_offset
# define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
#endif

#ifndef ENTRY
# define ENTRY(name)			\
	.type name,  @function; 	\
	.globl name;			\
	.p2align 4;			\
name:					\
	cfi_startproc
#endif

#ifndef END
# define END(name)			\
	cfi_endproc;			\
	.size name, .-name
#endif

#define CFI_PUSH(REG)						\
  cfi_adjust_cfa_offset (4);					\
  cfi_rel_offset (REG, 0)

#define CFI_POP(REG)						\
  cfi_adjust_cfa_offset (-4);					\
  cfi_restore (REG)

#define PUSH(REG)	pushl REG; CFI_PUSH (REG)
#define POP(REG)	popl REG; CFI_POP (REG)

#ifndef USE_AS_STRNCMP
# define STR1		4
# define STR2		STR1+4
# define RETURN		ret

# define UPDATE_STRNCMP_COUNTER
#else
# define STR1		8
# define STR2		STR1+4
# define CNT		STR2+4
# define RETURN		POP (%ebp); ret; CFI_PUSH (%ebp)

# define UPDATE_STRNCMP_COUNTER				\
	/* calculate left number to compare */		\
	mov	$16, %esi;				\
	sub	%ecx, %esi;				\
	cmp	%esi, %ebp;				\
	jbe	L(more8byteseq);			\
	sub	%esi, %ebp
#endif

	.section .text.ssse3,"ax",@progbits
ENTRY (ssse3_strcmp_latest)
#ifdef USE_AS_STRNCMP
	PUSH	(%ebp)
#endif
	movl	STR1(%esp), %edx
	movl	STR2(%esp), %eax
#ifdef USE_AS_STRNCMP
	movl	CNT(%esp), %ebp
	cmp	$16, %ebp
	jb	L(less16bytes_sncmp)
	jmp	L(more16bytes)
#endif

	movzbl	(%eax), %ecx
	cmpb	%cl, (%edx)
	jne	L(neq)
	cmpl	$0, %ecx
	je	L(eq)

	movzbl	1(%eax), %ecx
	cmpb	%cl, 1(%edx)
	jne	L(neq)
	cmpl	$0, %ecx
	je	L(eq)

	movzbl	2(%eax), %ecx
	cmpb	%cl, 2(%edx)
	jne	L(neq)
	cmpl	$0, %ecx
	je	L(eq)

	movzbl	3(%eax), %ecx
	cmpb	%cl, 3(%edx)
	jne	L(neq)
	cmpl	$0, %ecx
	je	L(eq)

	movzbl	4(%eax), %ecx
	cmpb	%cl, 4(%edx)
	jne	L(neq)
	cmpl	$0, %ecx
	je	L(eq)

	movzbl	5(%eax), %ecx
	cmpb	%cl, 5(%edx)
	jne	L(neq)
	cmpl	$0, %ecx
	je	L(eq)

	movzbl	6(%eax), %ecx
	cmpb	%cl, 6(%edx)
	jne	L(neq)
	cmpl	$0, %ecx
	je	L(eq)

	movzbl	7(%eax), %ecx
	cmpb	%cl, 7(%edx)
	jne	L(neq)
	cmpl	$0, %ecx
	je	L(eq)

	add	$8, %edx
	add	$8, %eax
#ifdef USE_AS_STRNCMP
	cmp	$8, %ebp
	lea	-8(%ebp), %ebp
	je	L(eq)
L(more16bytes):
#endif
	movl	%edx, %ecx
	and	$0xfff, %ecx
	cmp	$0xff0, %ecx
	ja	L(crosspage)
	mov	%eax, %ecx
	and	$0xfff, %ecx
	cmp	$0xff0, %ecx
	ja	L(crosspage)
	pxor	%xmm0, %xmm0
	movlpd	(%eax), %xmm1
	movlpd	(%edx), %xmm2
	movhpd	8(%eax), %xmm1
	movhpd	8(%edx), %xmm2
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %ecx
	sub	$0xffff, %ecx
	jnz	L(less16bytes)
#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(eq)
#endif
	add	$16, %eax
	add	$16, %edx

L(crosspage):

	PUSH	(%ebx)
	PUSH	(%edi)
	PUSH	(%esi)

	movl	%edx, %edi
	movl	%eax, %ecx
	and	$0xf, %ecx
	and	$0xf, %edi
	xor	%ecx, %eax
	xor	%edi, %edx
	xor	%ebx, %ebx
	cmp	%edi, %ecx
	je	L(ashr_0)
	ja	L(bigger)
	or	$0x20, %ebx
	xchg	%edx, %eax
	xchg	%ecx, %edi
L(bigger):
	lea	15(%edi), %edi
	sub	%ecx, %edi
	cmp	$8, %edi
	jle	L(ashr_less_8)
	cmp	$14, %edi
	je	L(ashr_15)
	cmp	$13, %edi
	je	L(ashr_14)
	cmp	$12, %edi
	je	L(ashr_13)
	cmp	$11, %edi
	je	L(ashr_12)
	cmp	$10, %edi
	je	L(ashr_11)
	cmp	$9, %edi
	je	L(ashr_10)
L(ashr_less_8):
	je	L(ashr_9)
	cmp	$7, %edi
	je	L(ashr_8)
	cmp	$6, %edi
	je	L(ashr_7)
	cmp	$5, %edi
	je	L(ashr_6)
	cmp	$4, %edi
	je	L(ashr_5)
	cmp	$3, %edi
	je	L(ashr_4)
	cmp	$2, %edi
	je	L(ashr_3)
	cmp	$1, %edi
	je	L(ashr_2)
	cmp	$0, %edi
	je	L(ashr_1)

/*
 * The following cases will be handled by ashr_0
 *  ecx(offset of esi)  eax(offset of edi)  relative offset  corresponding case
 *        n(0~15)            n(0~15)           15(15+ n-n)         ashr_0
 */
	.p2align 4
L(ashr_0):
	mov	$0xffff, %esi
	movdqa	(%eax), %xmm1
	pxor	%xmm0, %xmm0
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	(%edx), %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	mov	%ecx, %edi
	jne	L(less32bytes)
	UPDATE_STRNCMP_COUNTER
	mov	$0x10, %ebx
	mov	$0x10, %ecx
	pxor	%xmm0, %xmm0
	.p2align 4
L(loop_ashr_0):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)
#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	jmp	L(loop_ashr_0)

/*
 * The following cases will be handled by ashr_1
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(15)            n -15            0(15 +(n-15) - n)         ashr_1
 */
	.p2align 4
L(ashr_1):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$15, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-15(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$1, %ebx
	lea	1(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_1):
	add	$16, %edi
	jg	L(nibble_ashr_1)

L(gobble_ashr_1):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$1, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)
#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif

	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_1)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$1, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_1)

	.p2align 4
L(nibble_ashr_1):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xfffe, %esi
	jnz	L(ashr_1_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$15, %ebp
	jbe	L(ashr_1_exittail)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_1)

	.p2align 4
L(ashr_1_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$1, %xmm0
	psrldq	$1, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_2
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(14~15)            n -14            1(15 +(n-14) - n)         ashr_2
 */
	.p2align 4
L(ashr_2):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$14, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-14(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$2, %ebx
	lea	2(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_2):
	add	$16, %edi
	jg	L(nibble_ashr_2)

L(gobble_ashr_2):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$2, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_2)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$2, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_2)

	.p2align 4
L(nibble_ashr_2):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xfffc, %esi
	jnz	L(ashr_2_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$14, %ebp
	jbe	L(ashr_2_exittail)
#endif

	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_2)

	.p2align 4
L(ashr_2_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$2, %xmm0
	psrldq	$2, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_3
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(13~15)            n -13            2(15 +(n-13) - n)         ashr_3
 */
	.p2align 4
L(ashr_3):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$13, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-13(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$3, %ebx
	lea	3(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_3):
	add	$16, %edi
	jg	L(nibble_ashr_3)

L(gobble_ashr_3):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$3, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_3)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$3, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_3)

	.p2align 4
L(nibble_ashr_3):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xfff8, %esi
	jnz	L(ashr_3_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$13, %ebp
	jbe	L(ashr_3_exittail)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_3)

	.p2align 4
L(ashr_3_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$3, %xmm0
	psrldq	$3, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_4
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(12~15)            n -12            3(15 +(n-12) - n)         ashr_4
 */
	.p2align 4
L(ashr_4):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$12, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-12(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$4, %ebx
	lea	4(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_4):
	add	$16, %edi
	jg	L(nibble_ashr_4)

L(gobble_ashr_4):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$4, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif

	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_4)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$4, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif

	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_4)

	.p2align 4
L(nibble_ashr_4):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xfff0, %esi
	jnz	L(ashr_4_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$12, %ebp
	jbe	L(ashr_4_exittail)
#endif

	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_4)

	.p2align 4
L(ashr_4_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$4, %xmm0
	psrldq	$4, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_5
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(11~15)            n -11            4(15 +(n-11) - n)         ashr_5
 */
	.p2align 4
L(ashr_5):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$11, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-11(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$5, %ebx
	lea	5(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_5):
	add	$16, %edi
	jg	L(nibble_ashr_5)

L(gobble_ashr_5):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$5, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_5)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$5, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_5)

	.p2align 4
L(nibble_ashr_5):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xffe0, %esi
	jnz	L(ashr_5_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$11, %ebp
	jbe	L(ashr_5_exittail)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_5)

	.p2align 4
L(ashr_5_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$5, %xmm0
	psrldq	$5, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_6
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(10~15)            n -10            5(15 +(n-10) - n)         ashr_6
 */

	.p2align 4
L(ashr_6):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$10, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-10(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$6, %ebx
	lea	6(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_6):
	add	$16, %edi
	jg	L(nibble_ashr_6)

L(gobble_ashr_6):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$6, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif

	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_6)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$6, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)
#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif

	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_6)

	.p2align 4
L(nibble_ashr_6):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xffc0, %esi
	jnz	L(ashr_6_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$10, %ebp
	jbe	L(ashr_6_exittail)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_6)

	.p2align 4
L(ashr_6_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$6, %xmm0
	psrldq	$6, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_7
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(9~15)            n - 9            6(15 +(n-9) - n)         ashr_7
 */

	.p2align 4
L(ashr_7):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$9, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-9(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$7, %ebx
	lea	8(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_7):
	add	$16, %edi
	jg	L(nibble_ashr_7)

L(gobble_ashr_7):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$7, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif

	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_7)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$7, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif

	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_7)

	.p2align 4
L(nibble_ashr_7):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xff80, %esi
	jnz	L(ashr_7_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$9, %ebp
	jbe	L(ashr_7_exittail)
#endif
	pxor	%xmm0, %xmm0
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_7)

	.p2align 4
L(ashr_7_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$7, %xmm0
	psrldq	$7, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_8
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(8~15)            n - 8            7(15 +(n-8) - n)         ashr_8
 */
	.p2align 4
L(ashr_8):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$8, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-8(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$8, %ebx
	lea	8(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_8):
	add	$16, %edi
	jg	L(nibble_ashr_8)

L(gobble_ashr_8):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$8, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_8)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$8, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_8)

	.p2align 4
L(nibble_ashr_8):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xff00, %esi
	jnz	L(ashr_8_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$8, %ebp
	jbe	L(ashr_8_exittail)
#endif
	pxor	%xmm0, %xmm0
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_8)

	.p2align 4
L(ashr_8_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$8, %xmm0
	psrldq	$8, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_9
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(7~15)            n - 7            8(15 +(n-7) - n)         ashr_9
 */
	.p2align 4
L(ashr_9):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$7, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-7(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$9, %ebx
	lea	9(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_9):
	add	$16, %edi
	jg	L(nibble_ashr_9)

L(gobble_ashr_9):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$9, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_9)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$9, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_9)

	.p2align 4
L(nibble_ashr_9):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xfe00, %esi
	jnz	L(ashr_9_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$7, %ebp
	jbe	L(ashr_9_exittail)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_9)

	.p2align 4
L(ashr_9_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$9, %xmm0
	psrldq	$9, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_10
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(6~15)            n - 6            9(15 +(n-6) - n)         ashr_10
 */
	.p2align 4
L(ashr_10):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$6, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-6(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$10, %ebx
	lea	10(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_10):
	add	$16, %edi
	jg	L(nibble_ashr_10)

L(gobble_ashr_10):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$10, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_10)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$10, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_10)

	.p2align 4
L(nibble_ashr_10):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xfc00, %esi
	jnz	L(ashr_10_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$6, %ebp
	jbe	L(ashr_10_exittail)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_10)

	.p2align 4
L(ashr_10_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$10, %xmm0
	psrldq	$10, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_11
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(5~15)            n - 5            10(15 +(n-5) - n)         ashr_11
 */
	.p2align 4
L(ashr_11):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$5, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-5(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$11, %ebx
	lea	11(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_11):
	add	$16, %edi
	jg	L(nibble_ashr_11)

L(gobble_ashr_11):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$11, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_11)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$11, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_11)

	.p2align 4
L(nibble_ashr_11):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xf800, %esi
	jnz	L(ashr_11_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$5, %ebp
	jbe	L(ashr_11_exittail)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_11)

	.p2align 4
L(ashr_11_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$11, %xmm0
	psrldq	$11, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_12
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(4~15)            n - 4            11(15 +(n-4) - n)         ashr_12
 */
	.p2align 4
L(ashr_12):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$4, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-4(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$12, %ebx
	lea	12(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_12):
	add	$16, %edi
	jg	L(nibble_ashr_12)

L(gobble_ashr_12):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$12, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_12)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$12, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_12)

	.p2align 4
L(nibble_ashr_12):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xf000, %esi
	jnz	L(ashr_12_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$4, %ebp
	jbe	L(ashr_12_exittail)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_12)

	.p2align 4
L(ashr_12_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$12, %xmm0
	psrldq	$12, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_13
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(3~15)            n - 3            12(15 +(n-3) - n)         ashr_13
 */
	.p2align 4
L(ashr_13):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$3, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-3(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$13, %ebx
	lea	13(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_13):
	add	$16, %edi
	jg	L(nibble_ashr_13)

L(gobble_ashr_13):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$13, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_13)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$13, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_13)

	.p2align 4
L(nibble_ashr_13):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xe000, %esi
	jnz	L(ashr_13_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$3, %ebp
	jbe	L(ashr_13_exittail)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_13)

	.p2align 4
L(ashr_13_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$13, %xmm0
	psrldq	$13, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_14
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(2~15)            n - 2            13(15 +(n-2) - n)         ashr_14
 */
	.p2align 4
L(ashr_14):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$2, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-2(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$14, %ebx
	lea	14(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_14):
	add	$16, %edi
	jg	L(nibble_ashr_14)

L(gobble_ashr_14):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$14, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_14)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$14, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_14)

	.p2align 4
L(nibble_ashr_14):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0xc000, %esi
	jnz	L(ashr_14_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$2, %ebp
	jbe	L(ashr_14_exittail)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_14)

	.p2align 4
L(ashr_14_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$14, %xmm0
	psrldq	$14, %xmm3
	jmp	L(aftertail)

/*
 * The following cases will be handled by ashr_14
 * ecx(offset of esi)  eax(offset of edi)   relative offset   	corresponding case
 *        n(1~15)            n - 1            14(15 +(n-1) - n)         ashr_15
 */

	.p2align 4
L(ashr_15):
	mov	$0xffff, %esi
	pxor	%xmm0, %xmm0
	movdqa	(%edx), %xmm2
	movdqa	(%eax), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$1, %xmm2
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %edi
	shr	%cl, %esi
	shr	%cl, %edi
	sub	%edi, %esi
	lea	-1(%ecx), %edi
	jnz	L(less32bytes)

	UPDATE_STRNCMP_COUNTER

	movdqa	(%edx), %xmm3
	pxor	%xmm0, %xmm0
	mov	$16, %ecx
	or	$15, %ebx
	lea	15(%edx), %edi
	and	$0xfff, %edi
	sub	$0x1000, %edi

	.p2align 4
L(loop_ashr_15):
	add	$16, %edi
	jg	L(nibble_ashr_15)

L(gobble_ashr_15):
	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$15, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3

	add	$16, %edi
	jg	L(nibble_ashr_15)

	movdqa	(%eax, %ecx), %xmm1
	movdqa	(%edx, %ecx), %xmm2
	movdqa	%xmm2, %xmm4

	palignr	$15, %xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	sub	$0xffff, %esi
	jnz	L(exit)

#ifdef USE_AS_STRNCMP
	cmp	$16, %ebp
	lea	-16(%ebp), %ebp
	jbe	L(more8byteseq)
#endif
	add	$16, %ecx
	movdqa	%xmm4, %xmm3
	jmp	L(loop_ashr_15)

	.p2align 4
L(nibble_ashr_15):
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %esi
	test	$0x8000, %esi
	jnz	L(ashr_15_exittail)

#ifdef USE_AS_STRNCMP
	cmp	$1, %ebp
	jbe	L(ashr_15_exittail)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %edi
	jmp	L(gobble_ashr_15)

	.p2align 4
L(ashr_15_exittail):
	movdqa	(%eax, %ecx), %xmm1
	psrldq	$15, %xmm0
	psrldq	$15, %xmm3
	jmp	L(aftertail)

	.p2align 4
L(aftertail):
	pcmpeqb	%xmm3, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %esi
	not	%esi
L(exit):
	mov	%ebx, %edi
	and	$0x1f, %edi
	lea	-16(%edi, %ecx), %edi
L(less32bytes):
	add	%edi, %edx
	add	%ecx, %eax
	test	$0x20, %ebx
	jz	L(ret2)
	xchg	%eax, %edx

	.p2align 4
L(ret2):
	mov	%esi, %ecx
	POP	(%esi)
	POP	(%edi)
	POP	(%ebx)
L(less16bytes):
	test	%cl, %cl
	jz	L(2next_8_bytes)

	test	$0x01, %cl
	jnz	L(Byte0)

	test	$0x02, %cl
	jnz	L(Byte1)

	test	$0x04, %cl
	jnz	L(Byte2)

	test	$0x08, %cl
	jnz	L(Byte3)

	test	$0x10, %cl
	jnz	L(Byte4)

	test	$0x20, %cl
	jnz	L(Byte5)

	test	$0x40, %cl
	jnz	L(Byte6)
#ifdef USE_AS_STRNCMP
	cmp	$7, %ebp
	jbe	L(eq)
#endif

	movzx	7(%eax), %ecx
	movzx	7(%edx), %eax

	sub	%ecx, %eax
	RETURN

	.p2align 4
L(Byte0):
#ifdef USE_AS_STRNCMP
	cmp	$0, %ebp
	jbe	L(eq)
#endif
	movzx	(%eax), %ecx
	movzx	(%edx), %eax

	sub	%ecx, %eax
	RETURN

	.p2align 4
L(Byte1):
#ifdef USE_AS_STRNCMP
	cmp	$1, %ebp
	jbe	L(eq)
#endif
	movzx	1(%eax), %ecx
	movzx	1(%edx), %eax

	sub	%ecx, %eax
	RETURN

	.p2align 4
L(Byte2):
#ifdef USE_AS_STRNCMP
	cmp	$2, %ebp
	jbe	L(eq)
#endif
	movzx	2(%eax), %ecx
	movzx	2(%edx), %eax

	sub	%ecx, %eax
	RETURN

	.p2align 4
L(Byte3):
#ifdef USE_AS_STRNCMP
	cmp	$3, %ebp
	jbe	L(eq)
#endif
	movzx	3(%eax), %ecx
	movzx	3(%edx), %eax

	sub	%ecx, %eax
	RETURN

	.p2align 4
L(Byte4):
#ifdef USE_AS_STRNCMP
	cmp	$4, %ebp
	jbe	L(eq)
#endif
	movzx	4(%eax), %ecx
	movzx	4(%edx), %eax

	sub	%ecx, %eax
	RETURN

	.p2align 4
L(Byte5):
#ifdef USE_AS_STRNCMP
	cmp	$5, %ebp
	jbe	L(eq)
#endif
	movzx	5(%eax), %ecx
	movzx	5(%edx), %eax

	sub	%ecx, %eax
	RETURN

	.p2align 4
L(Byte6):
#ifdef USE_AS_STRNCMP
	cmp	$6, %ebp
	jbe	L(eq)
#endif
	movzx	6(%eax), %ecx
	movzx	6(%edx), %eax

	sub	%ecx, %eax
	RETURN

	.p2align 4
L(2next_8_bytes):
	add	$8, %eax
	add	$8, %edx
#ifdef USE_AS_STRNCMP
	cmp	$8, %ebp
	lea	-8(%ebp), %ebp
	jbe	L(eq)
#endif

	test	$0x01, %ch
	jnz	L(Byte0)

	test	$0x02, %ch
	jnz	L(Byte1)

	test	$0x04, %ch
	jnz	L(Byte2)

	test	$0x08, %ch
	jnz	L(Byte3)

	test	$0x10, %ch
	jnz	L(Byte4)

	test	$0x20, %ch
	jnz	L(Byte5)

	test	$0x40, %ch
	jnz	L(Byte6)

#ifdef USE_AS_STRNCMP
	cmp	$7, %ebp
	jbe	L(eq)
#endif
	movzx	7(%eax), %ecx
	movzx	7(%edx), %eax

	sub	%ecx, %eax
	RETURN

	.p2align 4
L(neq):
	mov	$1, %eax
	ja	L(neq_bigger)
	neg	%eax
L(neq_bigger):
	RETURN

#ifdef USE_AS_STRNCMP
	CFI_PUSH (%ebx)
	CFI_PUSH (%edi)
	CFI_PUSH (%esi)

	.p2align 4
L(more8byteseq):
	POP	(%esi)
	POP	(%edi)
	POP	(%ebx)
#endif

L(eq):

#ifdef USE_AS_STRNCMP
	POP	(%ebp)
#endif
	xorl	%eax, %eax
	ret

#ifdef USE_AS_STRNCMP
	CFI_PUSH (%ebp)

	.p2align 4
L(less16bytes_sncmp):
	test	%ebp, %ebp
	jz	L(eq)

	movzbl	(%eax), %ecx
	cmpb	%cl, (%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$1, %ebp
	je	L(eq)

	movzbl	1(%eax), %ecx
	cmpb	%cl, 1(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$2, %ebp
	je	L(eq)

	movzbl	2(%eax), %ecx
	cmpb	%cl, 2(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$3, %ebp
	je	L(eq)

	movzbl	3(%eax), %ecx
	cmpb	%cl, 3(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$4, %ebp
	je	L(eq)

	movzbl	4(%eax), %ecx
	cmpb	%cl, 4(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$5, %ebp
	je	L(eq)

	movzbl	5(%eax), %ecx
	cmpb	%cl, 5(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$6, %ebp
	je	L(eq)

	movzbl	6(%eax), %ecx
	cmpb	%cl, 6(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$7, %ebp
	je	L(eq)

	movzbl	7(%eax), %ecx
	cmpb	%cl, 7(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)


	cmp	$8, %ebp
	je	L(eq)

	movzbl	8(%eax), %ecx
	cmpb	%cl, 8(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$9, %ebp
	je	L(eq)

	movzbl	9(%eax), %ecx
	cmpb	%cl, 9(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$10, %ebp
	je	L(eq)

	movzbl	10(%eax), %ecx
	cmpb	%cl, 10(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$11, %ebp
	je	L(eq)

	movzbl	11(%eax), %ecx
	cmpb	%cl, 11(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)


	cmp	$12, %ebp
	je	L(eq)

	movzbl	12(%eax), %ecx
	cmpb	%cl, 12(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$13, %ebp
	je	L(eq)

	movzbl	13(%eax), %ecx
	cmpb	%cl, 13(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$14, %ebp
	je	L(eq)

	movzbl	14(%eax), %ecx
	cmpb	%cl, 14(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	cmp	$15, %ebp
	je	L(eq)

	movzbl	15(%eax), %ecx
	cmpb	%cl, 15(%edx)
	jne	L(neq)
	test	%cl, %cl
	je	L(eq)

	POP	(%ebp)
	xor	%eax, %eax
	ret
#endif

END (ssse3_strcmp_latest)
