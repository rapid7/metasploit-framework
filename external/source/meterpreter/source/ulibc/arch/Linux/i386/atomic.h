/*-
 * Copyright (c) 1998 Doug Rabson
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
 * $FreeBSD: head/sys/i386/include/atomic.h 185720 2008-12-06 21:33:44Z kib $
 */
#ifndef _MACHINE_ATOMIC_H_
#define	_MACHINE_ATOMIC_H_

#ifndef _SYS_CDEFS_H_
#error this file needs sys/cdefs.h as a prerequisite
#endif


#define	mb()	__asm __volatile("lock; addl $0,(%%esp)" : : : "memory")
#define	wmb()	__asm __volatile("lock; addl $0,(%%esp)" : : : "memory")
#define	rmb()	__asm __volatile("lock; addl $0,(%%esp)" : : : "memory")

/*
 * Various simple operations on memory, each of which is atomic in the
 * presence of interrupts and multiple processors.
 *
 * atomic_set_char(P, V)	(*(u_char *)(P) |= (V))
 * atomic_clear_char(P, V)	(*(u_char *)(P) &= ~(V))
 * atomic_add_char(P, V)	(*(u_char *)(P) += (V))
 * atomic_subtract_char(P, V)	(*(u_char *)(P) -= (V))
 *
 * atomic_set_short(P, V)	(*(u_short *)(P) |= (V))
 * atomic_clear_short(P, V)	(*(u_short *)(P) &= ~(V))
 * atomic_add_short(P, V)	(*(u_short *)(P) += (V))
 * atomic_subtract_short(P, V)	(*(u_short *)(P) -= (V))
 *
 * atomic_set_int(P, V)		(*(u_int *)(P) |= (V))
 * atomic_clear_int(P, V)	(*(u_int *)(P) &= ~(V))
 * atomic_add_int(P, V)		(*(u_int *)(P) += (V))
 * atomic_subtract_int(P, V)	(*(u_int *)(P) -= (V))
 * atomic_readandclear_int(P)	(return (*(u_int *)(P)); *(u_int *)(P) = 0;)
 *
 * atomic_set_long(P, V)	(*(u_long *)(P) |= (V))
 * atomic_clear_long(P, V)	(*(u_long *)(P) &= ~(V))
 * atomic_add_long(P, V)	(*(u_long *)(P) += (V))
 * atomic_subtract_long(P, V)	(*(u_long *)(P) -= (V))
 * atomic_readandclear_long(P)	(return (*(u_long *)(P)); *(u_long *)(P) = 0;)
 */

/*
 * The above functions are expanded inline in the statically-linked
 * kernel.  Lock prefixes are generated if an SMP kernel is being
 * built.
 *
 * Kernel modules call real functions which are built into the kernel.
 * This allows kernel modules to be portable between UP and SMP systems.
 */
#if defined(KLD_MODULE) || !defined(__GNUCLIKE_ASM)
#define	ATOMIC_ASM(NAME, TYPE, OP, CONS, V)			\
void atomic_##NAME##_##TYPE(volatile u_##TYPE *p, u_##TYPE v)

int	atomic_cmpset_int(volatile u_int *dst, u_int exp, u_int src);
u_int	atomic_fetchadd_int(volatile u_int *p, u_int v);

#define	ATOMIC_STORE_LOAD(TYPE, LOP, SOP)			\
u_##TYPE	atomic_load_acq_##TYPE(volatile u_##TYPE *p);	\
void		atomic_store_rel_##TYPE(volatile u_##TYPE *p, u_##TYPE v)

#else /* !KLD_MODULE && __GNUCLIKE_ASM */

/*
 * For userland, always use lock prefixes so that the binaries will run
 * on both SMP and !SMP systems.
 */
#if defined(SMP) || !defined(_KERNEL)
#define	MPLOCKED	"lock ; "
#else
#define	MPLOCKED
#endif

/*
 * The assembly is volatilized to demark potential before-and-after side
 * effects if an interrupt or SMP collision were to occur.
 */
#define	ATOMIC_ASM(NAME, TYPE, OP, CONS, V)		\
static __inline void					\
atomic_##NAME##_##TYPE(volatile u_##TYPE *p, u_##TYPE v)\
{							\
	__asm __volatile(MPLOCKED OP			\
	: "=m" (*p)					\
	: CONS (V), "m" (*p));				\
}							\
struct __hack

/*
 * Atomic compare and set, used by the mutex functions
 *
 * if (*dst == exp) *dst = src (all 32 bit words)
 *
 * Returns 0 on failure, non-zero on success
 */

#ifdef CPU_DISABLE_CMPXCHG

static __inline int
atomic_cmpset_int(volatile u_int *dst, u_int exp, u_int src)
{
	u_char res;

	__asm __volatile(
	"	pushfl ;		"
	"	cli ;			"
	"	cmpl	%3,%4 ;		"
	"	jne	1f ;		"
	"	movl	%2,%1 ;		"
	"1:				"
	"       sete	%0 ;		"
	"	popfl ;			"
	"# atomic_cmpset_int"
	: "=q" (res),			/* 0 */
	  "=m" (*dst)			/* 1 */
	: "r" (src),			/* 2 */
	  "r" (exp),			/* 3 */
	  "m" (*dst)			/* 4 */
	: "memory");

	return (res);
}

#else /* !CPU_DISABLE_CMPXCHG */

static __inline int
atomic_cmpset_int(volatile u_int *dst, u_int exp, u_int src)
{
	u_char res;

	__asm __volatile(
	"	" MPLOCKED "		"
	"	cmpxchgl %2,%1 ;	"
	"       sete	%0 ;		"
	"1:				"
	"# atomic_cmpset_int"
	: "=a" (res),			/* 0 */
	  "=m" (*dst)			/* 1 */
	: "r" (src),			/* 2 */
	  "a" (exp),			/* 3 */
	  "m" (*dst)			/* 4 */
	: "memory");

	return (res);
}

#endif /* CPU_DISABLE_CMPXCHG */

/*
 * Atomically add the value of v to the integer pointed to by p and return
 * the previous value of *p.
 */
static __inline u_int
atomic_fetchadd_int(volatile u_int *p, u_int v)
{

	__asm __volatile(
	"	" MPLOCKED "		"
	"	xaddl	%0, %1 ;	"
	"# atomic_fetchadd_int"
	: "+r" (v),			/* 0 (result) */
	  "=m" (*p)			/* 1 */
	: "m" (*p));			/* 2 */

	return (v);
}

#if defined(_KERNEL) && !defined(SMP)

/*
 * We assume that a = b will do atomic loads and stores.  However, on a
 * PentiumPro or higher, reads may pass writes, so for that case we have
 * to use a serializing instruction (i.e. with LOCK) to do the load in
 * SMP kernels.  For UP kernels, however, the cache of the single processor
 * is always consistent, so we don't need any memory barriers.
 */
#define	ATOMIC_STORE_LOAD(TYPE, LOP, SOP)		\
static __inline u_##TYPE				\
atomic_load_acq_##TYPE(volatile u_##TYPE *p)		\
{							\
	return (*p);					\
}							\
							\
static __inline void					\
atomic_store_rel_##TYPE(volatile u_##TYPE *p, u_##TYPE v)\
{							\
	*p = v;						\
}							\
struct __hack

#else /* !(_KERNEL && !SMP) */

#define	ATOMIC_STORE_LOAD(TYPE, LOP, SOP)		\
static __inline u_##TYPE				\
atomic_load_acq_##TYPE(volatile u_##TYPE *p)		\
{							\
	u_##TYPE res;					\
							\
	__asm __volatile(MPLOCKED LOP			\
	: "=a" (res),			/* 0 */		\
	  "=m" (*p)			/* 1 */		\
	: "m" (*p)			/* 2 */		\
	: "memory");					\
							\
	return (res);					\
}							\
							\
/*							\
 * The XCHG instruction asserts LOCK automagically.	\
 */							\
static __inline void					\
atomic_store_rel_##TYPE(volatile u_##TYPE *p, u_##TYPE v)\
{							\
	__asm __volatile(SOP				\
	: "=m" (*p),			/* 0 */		\
	  "+r" (v)			/* 1 */		\
	: "m" (*p));			/* 2 */		\
}							\
struct __hack

#endif /* _KERNEL && !SMP */

#endif /* KLD_MODULE || !__GNUCLIKE_ASM */

ATOMIC_ASM(set,	     char,  "orb %b1,%0",  "iq",  v);
ATOMIC_ASM(clear,    char,  "andb %b1,%0", "iq", ~v);
ATOMIC_ASM(add,	     char,  "addb %b1,%0", "iq",  v);
ATOMIC_ASM(subtract, char,  "subb %b1,%0", "iq",  v);

ATOMIC_ASM(set,	     short, "orw %w1,%0",  "ir",  v);
ATOMIC_ASM(clear,    short, "andw %w1,%0", "ir", ~v);
ATOMIC_ASM(add,	     short, "addw %w1,%0", "ir",  v);
ATOMIC_ASM(subtract, short, "subw %w1,%0", "ir",  v);

ATOMIC_ASM(set,	     int,   "orl %1,%0",   "ir",  v);
ATOMIC_ASM(clear,    int,   "andl %1,%0",  "ir", ~v);
ATOMIC_ASM(add,	     int,   "addl %1,%0",  "ir",  v);
ATOMIC_ASM(subtract, int,   "subl %1,%0",  "ir",  v);

ATOMIC_ASM(set,	     long,  "orl %1,%0",   "ir",  v);
ATOMIC_ASM(clear,    long,  "andl %1,%0",  "ir", ~v);
ATOMIC_ASM(add,	     long,  "addl %1,%0",  "ir",  v);
ATOMIC_ASM(subtract, long,  "subl %1,%0",  "ir",  v);

ATOMIC_STORE_LOAD(char,	"cmpxchgb %b0,%1", "xchgb %b1,%0");
ATOMIC_STORE_LOAD(short,"cmpxchgw %w0,%1", "xchgw %w1,%0");
ATOMIC_STORE_LOAD(int,	"cmpxchgl %0,%1",  "xchgl %1,%0");
ATOMIC_STORE_LOAD(long,	"cmpxchgl %0,%1",  "xchgl %1,%0");

#undef ATOMIC_ASM
#undef ATOMIC_STORE_LOAD

#ifndef WANT_FUNCTIONS

static __inline int
atomic_cmpset_long(volatile u_long *dst, u_long exp, u_long src)
{

	return (atomic_cmpset_int((volatile u_int *)dst, (u_int)exp,
	    (u_int)src));
}

static __inline u_long
atomic_fetchadd_long(volatile u_long *p, u_long v)
{

	return (atomic_fetchadd_int((volatile u_int *)p, (u_int)v));
}

/* Read the current value and store a zero in the destination. */
#ifdef __GNUCLIKE_ASM

static __inline u_int
atomic_readandclear_int(volatile u_int *addr)
{
	u_int res;

	res = 0;
	__asm __volatile(
	"	xchgl	%1,%0 ;		"
	"# atomic_readandclear_int"
	: "+r" (res),			/* 0 */
	  "=m" (*addr)			/* 1 */
	: "m" (*addr));

	return (res);
}

static __inline u_long
atomic_readandclear_long(volatile u_long *addr)
{
	u_long res;

	res = 0;
	__asm __volatile(
	"	xchgl	%1,%0 ;		"
	"# atomic_readandclear_long"
	: "+r" (res),			/* 0 */
	  "=m" (*addr)			/* 1 */
	: "m" (*addr));

	return (res);
}

#else /* !__GNUCLIKE_ASM */

u_int	atomic_readandclear_int(volatile u_int *addr);
u_long	atomic_readandclear_long(volatile u_long *addr);

#endif /* __GNUCLIKE_ASM */

/* Acquire and release variants are identical to the normal ones. */
#define	atomic_set_acq_char		atomic_set_char
#define	atomic_set_rel_char		atomic_set_char
#define	atomic_clear_acq_char		atomic_clear_char
#define	atomic_clear_rel_char		atomic_clear_char
#define	atomic_add_acq_char		atomic_add_char
#define	atomic_add_rel_char		atomic_add_char
#define	atomic_subtract_acq_char	atomic_subtract_char
#define	atomic_subtract_rel_char	atomic_subtract_char

#define	atomic_set_acq_short		atomic_set_short
#define	atomic_set_rel_short		atomic_set_short
#define	atomic_clear_acq_short		atomic_clear_short
#define	atomic_clear_rel_short		atomic_clear_short
#define	atomic_add_acq_short		atomic_add_short
#define	atomic_add_rel_short		atomic_add_short
#define	atomic_subtract_acq_short	atomic_subtract_short
#define	atomic_subtract_rel_short	atomic_subtract_short

#define	atomic_set_acq_int		atomic_set_int
#define	atomic_set_rel_int		atomic_set_int
#define	atomic_clear_acq_int		atomic_clear_int
#define	atomic_clear_rel_int		atomic_clear_int
#define	atomic_add_acq_int		atomic_add_int
#define	atomic_add_rel_int		atomic_add_int
#define	atomic_subtract_acq_int		atomic_subtract_int
#define	atomic_subtract_rel_int		atomic_subtract_int
#define	atomic_cmpset_acq_int		atomic_cmpset_int
#define	atomic_cmpset_rel_int		atomic_cmpset_int

#define	atomic_set_acq_long		atomic_set_long
#define	atomic_set_rel_long		atomic_set_long
#define	atomic_clear_acq_long		atomic_clear_long
#define	atomic_clear_rel_long		atomic_clear_long
#define	atomic_add_acq_long		atomic_add_long
#define	atomic_add_rel_long		atomic_add_long
#define	atomic_subtract_acq_long	atomic_subtract_long
#define	atomic_subtract_rel_long	atomic_subtract_long
#define	atomic_cmpset_acq_long		atomic_cmpset_long
#define	atomic_cmpset_rel_long		atomic_cmpset_long

/* Operations on 8-bit bytes. */
#define	atomic_set_8		atomic_set_char
#define	atomic_set_acq_8	atomic_set_acq_char
#define	atomic_set_rel_8	atomic_set_rel_char
#define	atomic_clear_8		atomic_clear_char
#define	atomic_clear_acq_8	atomic_clear_acq_char
#define	atomic_clear_rel_8	atomic_clear_rel_char
#define	atomic_add_8		atomic_add_char
#define	atomic_add_acq_8	atomic_add_acq_char
#define	atomic_add_rel_8	atomic_add_rel_char
#define	atomic_subtract_8	atomic_subtract_char
#define	atomic_subtract_acq_8	atomic_subtract_acq_char
#define	atomic_subtract_rel_8	atomic_subtract_rel_char
#define	atomic_load_acq_8	atomic_load_acq_char
#define	atomic_store_rel_8	atomic_store_rel_char

/* Operations on 16-bit words. */
#define	atomic_set_16		atomic_set_short
#define	atomic_set_acq_16	atomic_set_acq_short
#define	atomic_set_rel_16	atomic_set_rel_short
#define	atomic_clear_16		atomic_clear_short
#define	atomic_clear_acq_16	atomic_clear_acq_short
#define	atomic_clear_rel_16	atomic_clear_rel_short
#define	atomic_add_16		atomic_add_short
#define	atomic_add_acq_16	atomic_add_acq_short
#define	atomic_add_rel_16	atomic_add_rel_short
#define	atomic_subtract_16	atomic_subtract_short
#define	atomic_subtract_acq_16	atomic_subtract_acq_short
#define	atomic_subtract_rel_16	atomic_subtract_rel_short
#define	atomic_load_acq_16	atomic_load_acq_short
#define	atomic_store_rel_16	atomic_store_rel_short

/* Operations on 32-bit double words. */
#define	atomic_set_32		atomic_set_int
#define	atomic_set_acq_32	atomic_set_acq_int
#define	atomic_set_rel_32	atomic_set_rel_int
#define	atomic_clear_32		atomic_clear_int
#define	atomic_clear_acq_32	atomic_clear_acq_int
#define	atomic_clear_rel_32	atomic_clear_rel_int
#define	atomic_add_32		atomic_add_int
#define	atomic_add_acq_32	atomic_add_acq_int
#define	atomic_add_rel_32	atomic_add_rel_int
#define	atomic_subtract_32	atomic_subtract_int
#define	atomic_subtract_acq_32	atomic_subtract_acq_int
#define	atomic_subtract_rel_32	atomic_subtract_rel_int
#define	atomic_load_acq_32	atomic_load_acq_int
#define	atomic_store_rel_32	atomic_store_rel_int
#define	atomic_cmpset_32	atomic_cmpset_int
#define	atomic_cmpset_acq_32	atomic_cmpset_acq_int
#define	atomic_cmpset_rel_32	atomic_cmpset_rel_int
#define	atomic_readandclear_32	atomic_readandclear_int
#define	atomic_fetchadd_32	atomic_fetchadd_int

/* Operations on pointers. */
#define	atomic_set_ptr(p, v) \
	atomic_set_int((volatile u_int *)(p), (u_int)(v))
#define	atomic_set_acq_ptr(p, v) \
	atomic_set_acq_int((volatile u_int *)(p), (u_int)(v))
#define	atomic_set_rel_ptr(p, v) \
	atomic_set_rel_int((volatile u_int *)(p), (u_int)(v))
#define	atomic_clear_ptr(p, v) \
	atomic_clear_int((volatile u_int *)(p), (u_int)(v))
#define	atomic_clear_acq_ptr(p, v) \
	atomic_clear_acq_int((volatile u_int *)(p), (u_int)(v))
#define	atomic_clear_rel_ptr(p, v) \
	atomic_clear_rel_int((volatile u_int *)(p), (u_int)(v))
#define	atomic_add_ptr(p, v) \
	atomic_add_int((volatile u_int *)(p), (u_int)(v))
#define	atomic_add_acq_ptr(p, v) \
	atomic_add_acq_int((volatile u_int *)(p), (u_int)(v))
#define	atomic_add_rel_ptr(p, v) \
	atomic_add_rel_int((volatile u_int *)(p), (u_int)(v))
#define	atomic_subtract_ptr(p, v) \
	atomic_subtract_int((volatile u_int *)(p), (u_int)(v))
#define	atomic_subtract_acq_ptr(p, v) \
	atomic_subtract_acq_int((volatile u_int *)(p), (u_int)(v))
#define	atomic_subtract_rel_ptr(p, v) \
	atomic_subtract_rel_int((volatile u_int *)(p), (u_int)(v))
#define	atomic_load_acq_ptr(p) \
	atomic_load_acq_int((volatile u_int *)(p))
#define	atomic_store_rel_ptr(p, v) \
	atomic_store_rel_int((volatile u_int *)(p), (v))
#define	atomic_cmpset_ptr(dst, old, new) \
	atomic_cmpset_int((volatile u_int *)(dst), (u_int)(old), (u_int)(new))
#define	atomic_cmpset_acq_ptr(dst, old, new) \
	atomic_cmpset_acq_int((volatile u_int *)(dst), (u_int)(old), \
	    (u_int)(new))
#define	atomic_cmpset_rel_ptr(dst, old, new) \
	atomic_cmpset_rel_int((volatile u_int *)(dst), (u_int)(old), \
	    (u_int)(new))
#define	atomic_readandclear_ptr(p) \
	atomic_readandclear_int((volatile u_int *)(p))

#endif /* !WANT_FUNCTIONS */

#endif /* !_MACHINE_ATOMIC_H_ */
