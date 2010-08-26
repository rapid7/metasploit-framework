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

#ifndef MEMCPY
# define MEMCPY         ssse3_memcpy5
#endif

#ifndef L
# define L(label)	.L##label
#endif

#ifndef ALIGN
# define ALIGN(n)	.p2align n
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

#ifdef USE_AS_BCOPY
# define SRC		PARMS
# define DEST		SRC+4
# define LEN		DEST+4
#else
# define DEST		PARMS
# define SRC		DEST+4
# define LEN		SRC+4
#endif

#define CFI_PUSH(REG)						\
  cfi_adjust_cfa_offset (4);					\
  cfi_rel_offset (REG, 0)

#define CFI_POP(REG)						\
  cfi_adjust_cfa_offset (-4);					\
  cfi_restore (REG)

#define PUSH(REG)	pushl REG; CFI_PUSH (REG)
#define POP(REG)	popl REG; CFI_POP (REG)

#ifdef SHARED
# define PARMS		8		/* Preserve EBX.  */
# define ENTRANCE	PUSH (%ebx);
# define RETURN_END	POP (%ebx); ret
# define RETURN		RETURN_END; CFI_PUSH (%ebx)
# define JMPTBL(I, B)	I - B

/* Load an entry in a jump table into EBX and branch to it.  TABLE is a
   jump table with relative offsets.  INDEX is a register contains the
   index into the jump table.   SCALE is the scale of INDEX. */
# define BRANCH_TO_JMPTBL_ENTRY(TABLE, INDEX, SCALE)		\
    /* We first load PC into EBX.  */				\
    call	__i686.get_pc_thunk.bx;				\
    /* Get the address of the jump table.  */			\
    addl	$(TABLE - .), %ebx;				\
    /* Get the entry and convert the relative offset to the	\
       absolute address.  */					\
    addl	(%ebx,INDEX,SCALE), %ebx;			\
    /* We loaded the jump table.  Go.  */			\
    jmp		*%ebx

# define BRANCH_TO_JMPTBL_ENTRY_VALUE(TABLE)			\
    addl	$(TABLE - .), %ebx	
			
# define BRANCH_TO_JMPTBL_ENTRY_TAIL(TABLE, INDEX, SCALE)	\
    addl	(%ebx,INDEX,SCALE), %ebx;			\
    /* We loaded the jump table.  Go.  */			\
    jmp		*%ebx

	.section	.gnu.linkonce.t.__i686.get_pc_thunk.bx,"ax",@progbits
	.globl	__i686.get_pc_thunk.bx
	.hidden	__i686.get_pc_thunk.bx
	ALIGN (4)
	.type	__i686.get_pc_thunk.bx,@function
__i686.get_pc_thunk.bx:
	movl	(%esp), %ebx
	ret
#else
# define PARMS		4
# define ENTRANCE
# define RETURN_END	ret
# define RETURN		RETURN_END
# define JMPTBL(I, B)	I

/* Branch to an entry in a jump table.  TABLE is a jump table with
   absolute offsets.  INDEX is a register contains the index into the
   jump table.  SCALE is the scale of INDEX. */
# define BRANCH_TO_JMPTBL_ENTRY(TABLE, INDEX, SCALE)		\
    jmp		*TABLE(,INDEX,SCALE)

# define BRANCH_TO_JMPTBL_ENTRY_VALUE(TABLE)			

# define BRANCH_TO_JMPTBL_ENTRY_TAIL(TABLE, INDEX, SCALE)		\
    jmp		*TABLE(,INDEX,SCALE)
#endif

	.section .text.ssse3,"ax",@progbits
ENTRY (MEMCPY)
	ENTRANCE
	movl	LEN(%esp), %ecx
	movl	SRC(%esp), %eax
	movl	DEST(%esp), %edx

#ifdef USE_AS_MEMMOVE
	cmp	%eax, %edx
	jb	L(copy_forward)
	je	L(fwd_write_0bytes)
	cmp	$32, %ecx
	jae	L(memmove_bwd)
	jmp	L(bk_write_less32bytes_2)
L(memmove_bwd):
	add	%ecx, %eax
	cmp	%eax, %edx
	movl	SRC(%esp), %eax
	jb	L(copy_backward)

L(copy_forward):
#endif
	cmp	$48, %ecx
	jae	L(48bytesormore)

L(fwd_write_less32bytes):
#ifndef USE_AS_MEMMOVE
	cmp	%dl, %al
	jb	L(bk_write)
#endif
	add	%ecx, %edx
	add	%ecx, %eax
	BRANCH_TO_JMPTBL_ENTRY (L(table_48bytes_fwd), %ecx, 4)
#ifndef USE_AS_MEMMOVE
L(bk_write):
	BRANCH_TO_JMPTBL_ENTRY (L(table_48_bytes_bwd), %ecx, 4)
#endif

	ALIGN (4)
/* ECX > 32 and EDX is 4 byte aligned.  */
L(48bytesormore):
	movdqu	(%eax), %xmm0
	PUSH (%edi)
	movl	%edx, %edi
	and	$-16, %edx
	PUSH (%esi)
	add	$16, %edx
	movl	%edi, %esi
	sub	%edx, %edi
	add	%edi, %ecx
	sub	%edi, %eax

#ifdef SHARED_CACHE_SIZE_HALF
	cmp	$SHARED_CACHE_SIZE_HALF, %ecx
#else
# ifdef SHARED
	call	__i686.get_pc_thunk.bx
	add	$_GLOBAL_OFFSET_TABLE_, %ebx
	cmp	__x86_shared_cache_size_half@GOTOFF(%ebx), %ecx
# else
	cmp	__x86_shared_cache_size_half, %ecx
# endif
#endif

	mov	%eax, %edi
	jae	L(large_page)
	and	$0xf, %edi
	jz	L(shl_0)

	BRANCH_TO_JMPTBL_ENTRY (L(shl_table), %edi, 4)

	ALIGN (4)
L(shl_0):
	movdqu	%xmm0, (%esi)
	xor	%edi, %edi
	POP (%esi)
	cmp	$127, %ecx
	ja	L(shl_0_gobble)
	lea	-32(%ecx), %ecx
L(shl_0_loop):
	movdqa	(%eax, %edi), %xmm0
	movdqa	16(%eax, %edi), %xmm1
	sub	$32, %ecx
	movdqa	%xmm0, (%edx, %edi)
	movdqa	%xmm1, 16(%edx, %edi)
	lea	32(%edi), %edi
	jb	L(shl_0_end)

	movdqa	(%eax, %edi), %xmm0
	movdqa	16(%eax, %edi), %xmm1
	sub	$32, %ecx
	movdqa	%xmm0, (%edx, %edi)
	movdqa	%xmm1, 16(%edx, %edi)
	lea	32(%edi), %edi
	jb	L(shl_0_end)

	movdqa	(%eax, %edi), %xmm0
	movdqa	16(%eax, %edi), %xmm1
	sub	$32, %ecx
	movdqa	%xmm0, (%edx, %edi)
	movdqa	%xmm1, 16(%edx, %edi)
	lea	32(%edi), %edi
	jb	L(shl_0_end)

	movdqa	(%eax, %edi), %xmm0
	movdqa	16(%eax, %edi), %xmm1
	sub	$32, %ecx
	movdqa	%xmm0, (%edx, %edi)
	movdqa	%xmm1, 16(%edx, %edi)
	lea	32(%edi), %edi
L(shl_0_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	add	%edi, %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY (L(table_48bytes_fwd), %ecx, 4)

L(shl_0_gobble):

#ifdef DATA_CACHE_SIZE_HALF
	cmp	$DATA_CACHE_SIZE_HALF, %ecx
#else
# ifdef SHARED
	call	__i686.get_pc_thunk.bx
	add	$_GLOBAL_OFFSET_TABLE_, %ebx
	cmp	__x86_data_cache_size_half@GOTOFF(%ebx), %ecx
# else
	cmp	__x86_data_cache_size_half, %ecx
# endif
#endif

	POP (%edi)
	lea	-128(%ecx), %ecx
	jae	L(shl_0_gobble_mem_loop)
L(shl_0_gobble_cache_loop):
	movdqa	(%eax), %xmm0
	movdqa	0x10(%eax), %xmm1
	movdqa	0x20(%eax), %xmm2
	movdqa	0x30(%eax), %xmm3
	movdqa	0x40(%eax), %xmm4
	movdqa	0x50(%eax), %xmm5
	movdqa	0x60(%eax), %xmm6
	movdqa	0x70(%eax), %xmm7
	lea	0x80(%eax), %eax
	sub	$128, %ecx
	movdqa	%xmm0, (%edx)
	movdqa	%xmm1, 0x10(%edx)
	movdqa	%xmm2, 0x20(%edx)
	movdqa	%xmm3, 0x30(%edx)
	movdqa	%xmm4, 0x40(%edx)
	movdqa	%xmm5, 0x50(%edx)
	movdqa	%xmm6, 0x60(%edx)
	movdqa	%xmm7, 0x70(%edx)
	lea	0x80(%edx), %edx

	jae	L(shl_0_gobble_cache_loop)
	cmp	$-0x40, %ecx
	lea	0x80(%ecx), %ecx
	jl	L(shl_0_cache_less_64bytes)

	movdqa	(%eax), %xmm0
	sub	$0x40, %ecx
	movdqa	0x10(%eax), %xmm1

	movdqa	%xmm0, (%edx)
	movdqa	%xmm1, 0x10(%edx)

	movdqa	0x20(%eax), %xmm0
	movdqa	0x30(%eax), %xmm1
	add	$0x40, %eax

	movdqa	%xmm0, 0x20(%edx)
	movdqa	%xmm1, 0x30(%edx)
	add	$0x40, %edx
L(shl_0_cache_less_64bytes):
	cmp	$0x20, %ecx
	jb	L(shl_0_cache_less_32bytes)
	movdqa	(%eax), %xmm0
	sub	$0x20, %ecx
	movdqa	0x10(%eax), %xmm1
	add	$0x20, %eax
	movdqa	%xmm0, (%edx)
	movdqa	%xmm1, 0x10(%edx)
	add	$0x20, %edx
L(shl_0_cache_less_32bytes):
	cmp	$0x10, %ecx
	jb	L(shl_0_cache_less_16bytes)
	sub	$0x10, %ecx
	movdqa	(%eax), %xmm0
	add	$0x10, %eax
	movdqa	%xmm0, (%edx)
	add	$0x10, %edx
L(shl_0_cache_less_16bytes):
	add	%ecx, %edx
	add	%ecx, %eax
	BRANCH_TO_JMPTBL_ENTRY (L(table_48bytes_fwd), %ecx, 4)


	ALIGN (4)
L(shl_0_gobble_mem_loop):
	prefetcht0 0x1c0(%eax)
	prefetcht0 0x280(%eax)
	prefetcht0 0x1c0(%edx)

	movdqa	(%eax), %xmm0
	movdqa	0x10(%eax), %xmm1
	movdqa	0x20(%eax), %xmm2
	movdqa	0x30(%eax), %xmm3
	movdqa	0x40(%eax), %xmm4
	movdqa	0x50(%eax), %xmm5
	movdqa	0x60(%eax), %xmm6
	movdqa	0x70(%eax), %xmm7
	lea	0x80(%eax), %eax
	sub	$0x80, %ecx
	movdqa	%xmm0, (%edx)
	movdqa	%xmm1, 0x10(%edx)
	movdqa	%xmm2, 0x20(%edx)
	movdqa	%xmm3, 0x30(%edx)
	movdqa	%xmm4, 0x40(%edx)
	movdqa	%xmm5, 0x50(%edx)
	movdqa	%xmm6, 0x60(%edx)
	movdqa	%xmm7, 0x70(%edx)
	lea	0x80(%edx), %edx

	jae	L(shl_0_gobble_mem_loop)
	cmp	$-0x40, %ecx
	lea	0x80(%ecx), %ecx
	jl	L(shl_0_mem_less_64bytes)

	movdqa	(%eax), %xmm0
	sub	$0x40, %ecx
	movdqa	0x10(%eax), %xmm1

	movdqa	%xmm0, (%edx)
	movdqa	%xmm1, 0x10(%edx)

	movdqa	0x20(%eax), %xmm0
	movdqa	0x30(%eax), %xmm1
	add	$0x40, %eax

	movdqa	%xmm0, 0x20(%edx)
	movdqa	%xmm1, 0x30(%edx)
	add	$0x40, %edx
L(shl_0_mem_less_64bytes):
	cmp	$0x20, %ecx
	jb	L(shl_0_mem_less_32bytes)
	movdqa	(%eax), %xmm0
	sub	$0x20, %ecx
	movdqa	0x10(%eax), %xmm1
	add	$0x20, %eax
	movdqa	%xmm0, (%edx)
	movdqa	%xmm1, 0x10(%edx)
	add	$0x20, %edx
L(shl_0_mem_less_32bytes):
	cmp	$0x10, %ecx
	jb	L(shl_0_mem_less_16bytes)
	sub	$0x10, %ecx
	movdqa	(%eax), %xmm0
	add	$0x10, %eax
	movdqa	%xmm0, (%edx)
	add	$0x10, %edx
L(shl_0_mem_less_16bytes):
	add	%ecx, %edx
	add	%ecx, %eax
	BRANCH_TO_JMPTBL_ENTRY (L(table_48bytes_fwd), %ecx, 4)


	ALIGN (4)
L(shl_1):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-1(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_1_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$1, %xmm2, %xmm3
	palignr	$1, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_1_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$1, %xmm2, %xmm3
	palignr	$1, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_1_loop)

L(shl_1_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	1(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)

	ALIGN (4)
L(shl_2):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-2(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_2_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$2, %xmm2, %xmm3
	palignr	$2, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_2_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$2, %xmm2, %xmm3
	palignr	$2, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_2_loop)

L(shl_2_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	2(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)

	ALIGN (4)
L(shl_3):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-3(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_3_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$3, %xmm2, %xmm3
	palignr	$3, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_3_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$3, %xmm2, %xmm3
	palignr	$3, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_3_loop)

L(shl_3_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	3(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)

	ALIGN (4)
L(shl_4):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-4(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_4_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$4, %xmm2, %xmm3
	palignr	$4, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_4_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$4, %xmm2, %xmm3
	palignr	$4, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_4_loop)

L(shl_4_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	4(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)

	ALIGN (4)
L(shl_5):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-5(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_5_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$5, %xmm2, %xmm3
	palignr	$5, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_5_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$5, %xmm2, %xmm3
	palignr	$5, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_5_loop)

L(shl_5_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	5(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)


	ALIGN (4)
L(shl_6):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-6(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_6_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$6, %xmm2, %xmm3
	palignr	$6, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_6_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$6, %xmm2, %xmm3
	palignr	$6, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_6_loop)

L(shl_6_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	6(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)

	ALIGN (4)
L(shl_7):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-7(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_7_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$7, %xmm2, %xmm3
	palignr	$7, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_7_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$7, %xmm2, %xmm3
	palignr	$7, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_7_loop)

L(shl_7_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	7(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)

	ALIGN (4)
L(shl_8):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-8(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_8_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$8, %xmm2, %xmm3
	palignr	$8, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_8_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$8, %xmm2, %xmm3
	palignr	$8, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_8_loop)

L(shl_8_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	8(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)

	ALIGN (4)
L(shl_9):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-9(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_9_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$9, %xmm2, %xmm3
	palignr	$9, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_9_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$9, %xmm2, %xmm3
	palignr	$9, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_9_loop)

L(shl_9_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	9(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)

	ALIGN (4)
L(shl_10):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-10(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_10_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$10, %xmm2, %xmm3
	palignr	$10, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_10_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$10, %xmm2, %xmm3
	palignr	$10, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_10_loop)

L(shl_10_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	10(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)

	ALIGN (4)
L(shl_11):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-11(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_11_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$11, %xmm2, %xmm3
	palignr	$11, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_11_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$11, %xmm2, %xmm3
	palignr	$11, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_11_loop)

L(shl_11_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	11(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)

	ALIGN (4)
L(shl_12):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-12(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_12_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$12, %xmm2, %xmm3
	palignr	$12, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_12_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$12, %xmm2, %xmm3
	palignr	$12, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_12_loop)

L(shl_12_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	12(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)

	ALIGN (4)
L(shl_13):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-13(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_13_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$13, %xmm2, %xmm3
	palignr	$13, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_13_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$13, %xmm2, %xmm3
	palignr	$13, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_13_loop)

L(shl_13_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	13(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)

	ALIGN (4)
L(shl_14):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-14(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_14_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$14, %xmm2, %xmm3
	palignr	$14, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_14_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$14, %xmm2, %xmm3
	palignr	$14, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_14_loop)

L(shl_14_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	14(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)


	ALIGN (4)
L(shl_15):
	BRANCH_TO_JMPTBL_ENTRY_VALUE(L(table_48bytes_fwd))
	lea	-15(%eax), %eax
	movaps	(%eax), %xmm1
	xor	%edi, %edi
	lea	-32(%ecx), %ecx
	movdqu	%xmm0, (%esi)
	POP (%esi)
L(shl_15_loop):

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm4
	palignr	$15, %xmm2, %xmm3
	palignr	$15, %xmm1, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jb	L(shl_15_end)

	movdqa	16(%eax, %edi), %xmm2
	sub	$32, %ecx
	movdqa	32(%eax, %edi), %xmm3
	movdqa	%xmm3, %xmm1
	palignr	$15, %xmm2, %xmm3
	palignr	$15, %xmm4, %xmm2
	lea	32(%edi), %edi
	movdqa	%xmm2, -32(%edx, %edi)
	movdqa	%xmm3, -16(%edx, %edi)

	jae	L(shl_15_loop)

L(shl_15_end):
	lea	32(%ecx), %ecx
	add	%ecx, %edi
	add	%edi, %edx
	lea	15(%edi, %eax), %eax
	POP (%edi)
	BRANCH_TO_JMPTBL_ENTRY_TAIL(L(table_48bytes_fwd), %ecx, 4)


	ALIGN (4)
L(fwd_write_44bytes):
	movl	-44(%eax), %ecx
	movl	%ecx, -44(%edx)
L(fwd_write_40bytes):
	movl	-40(%eax), %ecx
	movl	%ecx, -40(%edx)
L(fwd_write_36bytes):
	movl	-36(%eax), %ecx
	movl	%ecx, -36(%edx)
L(fwd_write_32bytes):
	movl	-32(%eax), %ecx
	movl	%ecx, -32(%edx)
L(fwd_write_28bytes):
	movl	-28(%eax), %ecx
	movl	%ecx, -28(%edx)
L(fwd_write_24bytes):
	movl	-24(%eax), %ecx
	movl	%ecx, -24(%edx)
L(fwd_write_20bytes):
	movl	-20(%eax), %ecx
	movl	%ecx, -20(%edx)
L(fwd_write_16bytes):
	movl	-16(%eax), %ecx
	movl	%ecx, -16(%edx)
L(fwd_write_12bytes):
	movl	-12(%eax), %ecx
	movl	%ecx, -12(%edx)
L(fwd_write_8bytes):
	movl	-8(%eax), %ecx
	movl	%ecx, -8(%edx)
L(fwd_write_4bytes):
	movl	-4(%eax), %ecx
	movl	%ecx, -4(%edx)
L(fwd_write_0bytes):
#ifndef USE_AS_BCOPY
# ifdef USE_AS_MEMPCPY
	movl	%edx, %eax
# else
	movl	DEST(%esp), %eax
# endif
#endif
	RETURN

	ALIGN (4)
L(fwd_write_5bytes):
	movl	-5(%eax), %ecx
	movl	-4(%eax), %eax
	movl	%ecx, -5(%edx)
	movl	%eax, -4(%edx)
#ifndef USE_AS_BCOPY
# ifdef USE_AS_MEMPCPY
	movl	%edx, %eax
# else
	movl	DEST(%esp), %eax
# endif
#endif
	RETURN

	ALIGN (4)
L(fwd_write_45bytes):
	movl	-45(%eax), %ecx
	movl	%ecx, -45(%edx)
L(fwd_write_41bytes):
	movl	-41(%eax), %ecx
	movl	%ecx, -41(%edx)
L(fwd_write_37bytes):
	movl	-37(%eax), %ecx
	movl	%ecx, -37(%edx)
L(fwd_write_33bytes):
	movl	-33(%eax), %ecx
	movl	%ecx, -33(%edx)
L(fwd_write_29bytes):
	movl	-29(%eax), %ecx
	movl	%ecx, -29(%edx)
L(fwd_write_25bytes):
	movl	-25(%eax), %ecx
	movl	%ecx, -25(%edx)
L(fwd_write_21bytes):
	movl	-21(%eax), %ecx
	movl	%ecx, -21(%edx)
L(fwd_write_17bytes):
	movl	-17(%eax), %ecx
	movl	%ecx, -17(%edx)
L(fwd_write_13bytes):
	movl	-13(%eax), %ecx
	movl	%ecx, -13(%edx)
L(fwd_write_9bytes):
	movl	-9(%eax), %ecx
	movl	%ecx, -9(%edx)
	movl	-5(%eax), %ecx
	movl	%ecx, -5(%edx)
L(fwd_write_1bytes):
	movzbl	-1(%eax), %ecx
	movb	%cl, -1(%edx)
#ifndef USE_AS_BCOPY
# ifdef USE_AS_MEMPCPY
	movl	%edx, %eax
# else
	movl	DEST(%esp), %eax
# endif
#endif
	RETURN

	ALIGN (4)
L(fwd_write_46bytes):
	movl	-46(%eax), %ecx
	movl	%ecx, -46(%edx)
L(fwd_write_42bytes):
	movl	-42(%eax), %ecx
	movl	%ecx, -42(%edx)
L(fwd_write_38bytes):
	movl	-38(%eax), %ecx
	movl	%ecx, -38(%edx)
L(fwd_write_34bytes):
	movl	-34(%eax), %ecx
	movl	%ecx, -34(%edx)
L(fwd_write_30bytes):
	movl	-30(%eax), %ecx
	movl	%ecx, -30(%edx)
L(fwd_write_26bytes):
	movl	-26(%eax), %ecx
	movl	%ecx, -26(%edx)
L(fwd_write_22bytes):
	movl	-22(%eax), %ecx
	movl	%ecx, -22(%edx)
L(fwd_write_18bytes):
	movl	-18(%eax), %ecx
	movl	%ecx, -18(%edx)
L(fwd_write_14bytes):
	movl	-14(%eax), %ecx
	movl	%ecx, -14(%edx)
L(fwd_write_10bytes):
	movl	-10(%eax), %ecx
	movl	%ecx, -10(%edx)
L(fwd_write_6bytes):
	movl	-6(%eax), %ecx
	movl	%ecx, -6(%edx)
L(fwd_write_2bytes):
	movzwl	-2(%eax), %ecx
	movw	%cx, -2(%edx)
#ifndef USE_AS_BCOPY
# ifdef USE_AS_MEMPCPY
	movl	%edx, %eax
# else
	movl	DEST(%esp), %eax
# endif
#endif
	RETURN

	ALIGN (4)
L(fwd_write_47bytes):
	movl	-47(%eax), %ecx
	movl	%ecx, -47(%edx)
L(fwd_write_43bytes):
	movl	-43(%eax), %ecx
	movl	%ecx, -43(%edx)
L(fwd_write_39bytes):
	movl	-39(%eax), %ecx
	movl	%ecx, -39(%edx)
L(fwd_write_35bytes):
	movl	-35(%eax), %ecx
	movl	%ecx, -35(%edx)
L(fwd_write_31bytes):
	movl	-31(%eax), %ecx
	movl	%ecx, -31(%edx)
L(fwd_write_27bytes):
	movl	-27(%eax), %ecx
	movl	%ecx, -27(%edx)
L(fwd_write_23bytes):
	movl	-23(%eax), %ecx
	movl	%ecx, -23(%edx)
L(fwd_write_19bytes):
	movl	-19(%eax), %ecx
	movl	%ecx, -19(%edx)
L(fwd_write_15bytes):
	movl	-15(%eax), %ecx
	movl	%ecx, -15(%edx)
L(fwd_write_11bytes):
	movl	-11(%eax), %ecx
	movl	%ecx, -11(%edx)
L(fwd_write_7bytes):
	movl	-7(%eax), %ecx
	movl	%ecx, -7(%edx)
L(fwd_write_3bytes):
	movzwl	-3(%eax), %ecx
	movzbl	-1(%eax), %eax
	movw	%cx, -3(%edx)
	movb	%al, -1(%edx)
#ifndef USE_AS_BCOPY
# ifdef USE_AS_MEMPCPY
	movl	%edx, %eax
# else
	movl	DEST(%esp), %eax
# endif
#endif
	RETURN

	ALIGN (4)
L(large_page):
	movdqu	(%eax), %xmm1
	lea	16(%eax), %eax
	movdqu	%xmm0, (%esi)
	movntdq	%xmm1, (%edx)
	lea	16(%edx), %edx
	POP (%esi)
	lea	-0x90(%ecx), %ecx
	POP (%edi)
L(large_page_loop):
	movdqu	(%eax), %xmm0
	movdqu	0x10(%eax), %xmm1
	movdqu	0x20(%eax), %xmm2
	movdqu	0x30(%eax), %xmm3
	movdqu	0x40(%eax), %xmm4
	movdqu	0x50(%eax), %xmm5
	movdqu	0x60(%eax), %xmm6
	movdqu	0x70(%eax), %xmm7
	lea	0x80(%eax), %eax

	sub	$0x80, %ecx
	movntdq	%xmm0, (%edx)
	movntdq	%xmm1, 0x10(%edx)
	movntdq	%xmm2, 0x20(%edx)
	movntdq	%xmm3, 0x30(%edx)
	movntdq	%xmm4, 0x40(%edx)
	movntdq	%xmm5, 0x50(%edx)
	movntdq	%xmm6, 0x60(%edx)
	movntdq	%xmm7, 0x70(%edx)
	lea	0x80(%edx), %edx
	jae	L(large_page_loop)
	cmp	$-0x40, %ecx
	lea	0x80(%ecx), %ecx
	jl	L(large_page_less_64bytes)

	movdqu	(%eax), %xmm0
	movdqu	0x10(%eax), %xmm1
	movdqu	0x20(%eax), %xmm2
	movdqu	0x30(%eax), %xmm3
	lea	0x40(%eax), %eax

	movntdq	%xmm0, (%edx)
	movntdq	%xmm1, 0x10(%edx)
	movntdq	%xmm2, 0x20(%edx)
	movntdq	%xmm3, 0x30(%edx)
	lea	0x40(%edx), %edx
	sub	$0x40, %ecx
L(large_page_less_64bytes):
	cmp	$32, %ecx
	jb	L(large_page_less_32bytes)
	movdqu	(%eax), %xmm0
	movdqu	0x10(%eax), %xmm1
	lea	0x20(%eax), %eax
	movntdq	%xmm0, (%edx)
	movntdq	%xmm1, 0x10(%edx)
	lea	0x20(%edx), %edx
	sub	$0x20, %ecx
L(large_page_less_32bytes):
	add	%ecx, %edx
	add	%ecx, %eax
	sfence
	BRANCH_TO_JMPTBL_ENTRY (L(table_48bytes_fwd), %ecx, 4)


	ALIGN (4)
L(bk_write_44bytes):
	movl	40(%eax), %ecx
	movl	%ecx, 40(%edx)
L(bk_write_40bytes):
	movl	36(%eax), %ecx
	movl	%ecx, 36(%edx)
L(bk_write_36bytes):
	movl	32(%eax), %ecx
	movl	%ecx, 32(%edx)
L(bk_write_32bytes):
	movl	28(%eax), %ecx
	movl	%ecx, 28(%edx)
L(bk_write_28bytes):
	movl	24(%eax), %ecx
	movl	%ecx, 24(%edx)
L(bk_write_24bytes):
	movl	20(%eax), %ecx
	movl	%ecx, 20(%edx)
L(bk_write_20bytes):
	movl	16(%eax), %ecx
	movl	%ecx, 16(%edx)
L(bk_write_16bytes):
	movl	12(%eax), %ecx
	movl	%ecx, 12(%edx)
L(bk_write_12bytes):
	movl	8(%eax), %ecx
	movl	%ecx, 8(%edx)
L(bk_write_8bytes):
	movl	4(%eax), %ecx
	movl	%ecx, 4(%edx)
L(bk_write_4bytes):
	movl	(%eax), %ecx
	movl	%ecx, (%edx)
L(bk_write_0bytes):
#ifndef USE_AS_BCOPY
	movl	DEST(%esp), %eax
# ifdef USE_AS_MEMPCPY
	movl	LEN(%esp), %ecx
	add	%ecx, %eax
# endif
#endif
	RETURN

	ALIGN (4)
L(bk_write_45bytes):
	movl	41(%eax), %ecx
	movl	%ecx, 41(%edx)
L(bk_write_41bytes):
	movl	37(%eax), %ecx
	movl	%ecx, 37(%edx)
L(bk_write_37bytes):
	movl	33(%eax), %ecx
	movl	%ecx, 33(%edx)
L(bk_write_33bytes):
	movl	29(%eax), %ecx
	movl	%ecx, 29(%edx)
L(bk_write_29bytes):
	movl	25(%eax), %ecx
	movl	%ecx, 25(%edx)
L(bk_write_25bytes):
	movl	21(%eax), %ecx
	movl	%ecx, 21(%edx)
L(bk_write_21bytes):
	movl	17(%eax), %ecx
	movl	%ecx, 17(%edx)
L(bk_write_17bytes):
	movl	13(%eax), %ecx
	movl	%ecx, 13(%edx)
L(bk_write_13bytes):
	movl	9(%eax), %ecx
	movl	%ecx, 9(%edx)
L(bk_write_9bytes):
	movl	5(%eax), %ecx
	movl	%ecx, 5(%edx)
L(bk_write_5bytes):
	movl	1(%eax), %ecx
	movl	%ecx, 1(%edx)
L(bk_write_1bytes):
	movzbl	(%eax), %ecx
	movb	%cl, (%edx)
#ifndef USE_AS_BCOPY
	movl	DEST(%esp), %eax
# ifdef USE_AS_MEMPCPY
	movl	LEN(%esp), %ecx
	add	%ecx, %eax
# endif
#endif
	RETURN

	ALIGN (4)
L(bk_write_46bytes):
	movl	42(%eax), %ecx
	movl	%ecx, 42(%edx)
L(bk_write_42bytes):
	movl	38(%eax), %ecx
	movl	%ecx, 38(%edx)
L(bk_write_38bytes):
	movl	34(%eax), %ecx
	movl	%ecx, 34(%edx)
L(bk_write_34bytes):
	movl	30(%eax), %ecx
	movl	%ecx, 30(%edx)
L(bk_write_30bytes):
	movl	26(%eax), %ecx
	movl	%ecx, 26(%edx)
L(bk_write_26bytes):
	movl	22(%eax), %ecx
	movl	%ecx, 22(%edx)
L(bk_write_22bytes):
	movl	18(%eax), %ecx
	movl	%ecx, 18(%edx)
L(bk_write_18bytes):
	movl	14(%eax), %ecx
	movl	%ecx, 14(%edx)
L(bk_write_14bytes):
	movl	10(%eax), %ecx
	movl	%ecx, 10(%edx)
L(bk_write_10bytes):
	movl	6(%eax), %ecx
	movl	%ecx, 6(%edx)
L(bk_write_6bytes):
	movl	2(%eax), %ecx
	movl	%ecx, 2(%edx)
L(bk_write_2bytes):
	movzwl	(%eax), %ecx
	movw	%cx, (%edx)
#ifndef USE_AS_BCOPY
	movl	DEST(%esp), %eax
# ifdef USE_AS_MEMPCPY
	movl	LEN(%esp), %ecx
	add	%ecx, %eax
# endif
#endif
	RETURN

	ALIGN (4)
L(bk_write_47bytes):
	movl	43(%eax), %ecx
	movl	%ecx, 43(%edx)
L(bk_write_43bytes):
	movl	39(%eax), %ecx
	movl	%ecx, 39(%edx)
L(bk_write_39bytes):
	movl	35(%eax), %ecx
	movl	%ecx, 35(%edx)
L(bk_write_35bytes):
	movl	31(%eax), %ecx
	movl	%ecx, 31(%edx)
L(bk_write_31bytes):
	movl	27(%eax), %ecx
	movl	%ecx, 27(%edx)
L(bk_write_27bytes):
	movl	23(%eax), %ecx
	movl	%ecx, 23(%edx)
L(bk_write_23bytes):
	movl	19(%eax), %ecx
	movl	%ecx, 19(%edx)
L(bk_write_19bytes):
	movl	15(%eax), %ecx
	movl	%ecx, 15(%edx)
L(bk_write_15bytes):
	movl	11(%eax), %ecx
	movl	%ecx, 11(%edx)
L(bk_write_11bytes):
	movl	7(%eax), %ecx
	movl	%ecx, 7(%edx)
L(bk_write_7bytes):
	movl	3(%eax), %ecx
	movl	%ecx, 3(%edx)
L(bk_write_3bytes):
	movzwl	1(%eax), %ecx
	movw	%cx, 1(%edx)
	movzbl	(%eax), %eax
	movb	%al, (%edx)
#ifndef USE_AS_BCOPY
	movl	DEST(%esp), %eax
# ifdef USE_AS_MEMPCPY
	movl	LEN(%esp), %ecx
	add	%ecx, %eax
# endif
#endif
	RETURN_END


	.pushsection .rodata.ssse3,"a",@progbits
	ALIGN (2)
L(table_48bytes_fwd):
	.int	JMPTBL (L(fwd_write_0bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_1bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_2bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_3bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_4bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_5bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_6bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_7bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_8bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_9bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_10bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_11bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_12bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_13bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_14bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_15bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_16bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_17bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_18bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_19bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_20bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_21bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_22bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_23bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_24bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_25bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_26bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_27bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_28bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_29bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_30bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_31bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_32bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_33bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_34bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_35bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_36bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_37bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_38bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_39bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_40bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_41bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_42bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_43bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_44bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_45bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_46bytes), L(table_48bytes_fwd))
	.int	JMPTBL (L(fwd_write_47bytes), L(table_48bytes_fwd))

	ALIGN (2)
L(shl_table):
	.int	JMPTBL (L(shl_0), L(shl_table))
	.int	JMPTBL (L(shl_1), L(shl_table))
	.int	JMPTBL (L(shl_2), L(shl_table))
	.int	JMPTBL (L(shl_3), L(shl_table))
	.int	JMPTBL (L(shl_4), L(shl_table))
	.int	JMPTBL (L(shl_5), L(shl_table))
	.int	JMPTBL (L(shl_6), L(shl_table))
	.int	JMPTBL (L(shl_7), L(shl_table))
	.int	JMPTBL (L(shl_8), L(shl_table))
	.int	JMPTBL (L(shl_9), L(shl_table))
	.int	JMPTBL (L(shl_10), L(shl_table))
	.int	JMPTBL (L(shl_11), L(shl_table))
	.int	JMPTBL (L(shl_12), L(shl_table))
	.int	JMPTBL (L(shl_13), L(shl_table))
	.int	JMPTBL (L(shl_14), L(shl_table))
	.int	JMPTBL (L(shl_15), L(shl_table))

	ALIGN (2)
L(table_48_bytes_bwd):
	.int	JMPTBL (L(bk_write_0bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_1bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_2bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_3bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_4bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_5bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_6bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_7bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_8bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_9bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_10bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_11bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_12bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_13bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_14bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_15bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_16bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_17bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_18bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_19bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_20bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_21bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_22bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_23bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_24bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_25bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_26bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_27bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_28bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_29bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_30bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_31bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_32bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_33bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_34bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_35bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_36bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_37bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_38bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_39bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_40bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_41bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_42bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_43bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_44bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_45bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_46bytes), L(table_48_bytes_bwd))
	.int	JMPTBL (L(bk_write_47bytes), L(table_48_bytes_bwd))

	.popsection

#ifdef USE_AS_MEMMOVE
	ALIGN (4)
L(copy_backward):
	PUSH (%esi)
	movl	%eax, %esi
	lea	(%ecx,%edx,1),%edx
	lea	(%ecx,%esi,1),%esi
	testl	$0x3, %edx
	jnz	L(bk_align)

L(bk_aligned_4):
	cmp	$64, %ecx
	jae	L(bk_write_more64bytes)

L(bk_write_64bytesless):
	cmp	$32, %ecx
	jb	L(bk_write_less32bytes)

L(bk_write_more32bytes):
	/* Copy 32 bytes at a time.  */
	sub	$32, %ecx
	movl	-4(%esi), %eax
	movl	%eax, -4(%edx)
	movl	-8(%esi), %eax
	movl	%eax, -8(%edx)
	movl	-12(%esi), %eax
	movl	%eax, -12(%edx)
	movl	-16(%esi), %eax
	movl	%eax, -16(%edx)
	movl	-20(%esi), %eax
	movl	%eax, -20(%edx)
	movl	-24(%esi), %eax
	movl	%eax, -24(%edx)
	movl	-28(%esi), %eax
	movl	%eax, -28(%edx)
	movl	-32(%esi), %eax
	movl	%eax, -32(%edx)
	sub	$32, %edx
	sub	$32, %esi

L(bk_write_less32bytes):
	movl	%esi, %eax
	sub	%ecx, %edx
	sub	%ecx, %eax
	POP (%esi)
L(bk_write_less32bytes_2):
	BRANCH_TO_JMPTBL_ENTRY (L(table_48_bytes_bwd), %ecx, 4)

	ALIGN (4)
L(bk_align):
	cmp	$8, %ecx
	jbe	L(bk_write_less32bytes)
	testl	$1, %edx
	/* We get here only if (EDX & 3 ) != 0 so if (EDX & 1) ==0,
	   then (EDX & 2) must be != 0.  */
	jz	L(bk_got2)
	sub	$1, %esi
	sub	$1, %ecx
	sub	$1, %edx
	movzbl	(%esi), %eax
	movb	%al, (%edx)

	testl	$2, %edx
	jz	L(bk_aligned_4)

L(bk_got2):
	sub	$2, %esi
	sub	$2, %ecx
	sub	$2, %edx
	movzwl	(%esi), %eax
	movw	%ax, (%edx)
	jmp	L(bk_aligned_4)

	ALIGN (4)
L(bk_write_more64bytes):
	/* Check alignment of last byte.  */
	testl	$15, %edx
	jz	L(bk_ssse3_cpy_pre)

/* EDX is aligned 4 bytes, but not 16 bytes.  */
L(bk_ssse3_align):
	sub	$4, %esi
	sub	$4, %ecx
	sub	$4, %edx
	movl	(%esi), %eax
	movl	%eax, (%edx)

	testl	$15, %edx
	jz	L(bk_ssse3_cpy_pre)

	sub	$4, %esi
	sub	$4, %ecx
	sub	$4, %edx
	movl	(%esi), %eax
	movl	%eax, (%edx)

	testl	$15, %edx
	jz	L(bk_ssse3_cpy_pre)

	sub	$4, %esi
	sub	$4, %ecx
	sub	$4, %edx
	movl	(%esi), %eax
	movl	%eax, (%edx)

L(bk_ssse3_cpy_pre):
	cmp	$64, %ecx
	jb	L(bk_write_more32bytes)

L(bk_ssse3_cpy):
	sub	$64, %esi
	sub	$64, %ecx
	sub	$64, %edx
	movdqu	0x30(%esi), %xmm3
	movdqa	%xmm3, 0x30(%edx)
	movdqu	0x20(%esi), %xmm2
	movdqa	%xmm2, 0x20(%edx)
	movdqu	0x10(%esi), %xmm1
	movdqa	%xmm1, 0x10(%edx)
	movdqu	(%esi), %xmm0
	movdqa	%xmm0, (%edx)
	cmp	$64, %ecx
	jae	L(bk_ssse3_cpy)
	jmp	L(bk_write_64bytesless)

#endif

END (MEMCPY)
