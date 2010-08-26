/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/linux-syscalls.h>

.global __atomic_cmpxchg
.type __atomic_cmpxchg, %function
.global __atomic_swap
.type __atomic_swap, %function
.global __atomic_dec
.type __atomic_dec, %function
.global __atomic_inc
.type __atomic_inc, %function

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

#if 1
   .equ     kernel_cmpxchg, 0xFFFF0FC0
   .equ     kernel_atomic_base, 0xFFFF0FFF
__atomic_dec:
    .fnstart
    .save {r4, lr}
    stmdb   sp!, {r4, lr}
    mov     r2, r0
1: @ atomic_dec
    ldr     r0, [r2]
    mov     r3, #kernel_atomic_base
    add     lr, pc, #4
    sub     r1, r0, #1
    add     pc, r3, #(kernel_cmpxchg - kernel_atomic_base)
    bcc     1b
    add     r0, r1, #1
    ldmia   sp!, {r4, lr}
    bx      lr
    .fnend

__atomic_inc:
    .fnstart
    .save {r4, lr}
    stmdb   sp!, {r4, lr}
    mov     r2, r0
1: @ atomic_inc
    ldr     r0, [r2]
    mov     r3, #kernel_atomic_base
    add     lr, pc, #4
    add     r1, r0, #1
    add     pc, r3, #(kernel_cmpxchg - kernel_atomic_base)
    bcc     1b
    sub     r0, r1, #1
    ldmia   sp!, {r4, lr}
    bx      lr
    .fnend

/* r0(old) r1(new) r2(addr) -> r0(zero_if_succeeded) */
__atomic_cmpxchg:
    .fnstart
    .save {r4, lr}
    stmdb   sp!, {r4, lr}
    mov     r4, r0          /* r4 = save oldvalue */
1: @ atomic_cmpxchg
    mov     r3, #kernel_atomic_base
    add     lr, pc, #4
    mov     r0, r4          /* r0 = oldvalue */
    add     pc, r3, #(kernel_cmpxchg - kernel_atomic_base)
    bcs     2f              /* swap was made. we're good, return. */
    ldr     r3, [r2]        /* swap not made, see if it's because *ptr!=oldvalue */
    cmp     r3, r4
    beq     1b
2: @ atomic_cmpxchg
    ldmia   sp!, {r4, lr}
    bx      lr
    .fnend
#else
#define KUSER_CMPXCHG 0xffffffc0

/* r0(old) r1(new) r2(addr) -> r0(zero_if_succeeded) */
__atomic_cmpxchg:
    stmdb   sp!, {r4, lr}
    mov     r4, r0          /* r4 = save oldvalue */
1:  add     lr, pc, #4
    mov     r0, r4          /* r0 = oldvalue */
    mov     pc, #KUSER_CMPXCHG
    bcs     2f              /* swap was made. we're good, return. */
    ldr     r3, [r2]        /* swap not made, see if it's because *ptr!=oldvalue */
    cmp     r3, r4
    beq     1b
2:  ldmia   sp!, {r4, lr}
    bx      lr

/* r0(addr) -> r0(old) */
__atomic_dec:
    stmdb   sp!, {r4, lr}
    mov     r2, r0          /* address */
1:  ldr     r0, [r2]        /* oldvalue */
    add     lr, pc, #4
    sub     r1, r0, #1      /* newvalue = oldvalue - 1 */
    mov     pc, #KUSER_CMPXCHG
    bcc     1b              /* no swap, try again until we get it right */
    mov     r0, ip          /* swapped, return the old value */
    ldmia   sp!, {r4, lr}
    bx      lr

/* r0(addr) -> r0(old) */
__atomic_inc:
    stmdb   sp!, {r4, lr}
    mov     r2, r0          /* address */
1:  ldr     r0, [r2]        /* oldvalue */
    add     lr, pc, #4
    add     r1, r0, #1      /* newvalue = oldvalue + 1 */
    mov     pc, #KUSER_CMPXCHG
    bcc     1b              /* no swap, try again until we get it right */
    mov     r0, ip          /* swapped, return the old value */
    ldmia   sp!, {r4, lr}
    bx      lr
#endif

/* r0(new) r1(addr) -> r0(old) */
/* replaced swp instruction with ldrex/strex for ARMv6 & ARMv7 */
__atomic_swap:
#if defined (_ARM_HAVE_LDREX_STREX)
1:  ldrex   r2, [r1]
    strex   r3, r0, [r1]
    teq     r3, #0
    bne     1b
    mov     r0, r2
    mcr     p15, 0, r0, c7, c10, 5 /* or, use dmb */
#else
    swp     r0, r0, [r1]
#endif
    bx      lr

/* __futex_wait(*ftx, val, *timespec) */
/* __futex_wake(*ftx, counter) */
/* __futex_syscall3(*ftx, op, val) */
/* __futex_syscall4(*ftx, op, val, *timespec) */

.global __futex_wait
.type __futex_wait, %function

.global __futex_wake
.type __futex_wake, %function

.global __futex_syscall3
.type __futex_syscall3, %function

.global __futex_syscall4
.type __futex_syscall4, %function

#if __ARM_EABI__

__futex_syscall3:
    .fnstart
    stmdb   sp!, {r4, r7}
    .save   {r4, r7}
    ldr     r7, =__NR_futex
    swi     #0
    ldmia   sp!, {r4, r7}
    bx      lr
    .fnend

__futex_wait:
    .fnstart
    stmdb   sp!, {r4, r7}
    .save   {r4, r7}
    mov     r3, r2
    mov     r2, r1
    mov     r1, #FUTEX_WAIT
    ldr     r7, =__NR_futex
    swi     #0
    ldmia   sp!, {r4, r7}
    bx      lr
    .fnend

__futex_wake:
    stmdb   sp!, {r4, r7}
    mov     r2, r1
    mov     r1, #FUTEX_WAKE
    ldr     r7, =__NR_futex
    swi     #0
    ldmia   sp!, {r4, r7}
    bx      lr

#else

__futex_syscall3:
    swi     #__NR_futex
    bx      lr

__futex_wait:
    mov     r3, r2
    mov     r2, r1
    mov     r1, #FUTEX_WAIT
    swi     #__NR_futex
    bx      lr

__futex_wake:
    mov     r2, r1
    mov     r1, #FUTEX_WAKE
    swi     #__NR_futex
    bx      lr

#endif

__futex_syscall4:
    b __futex_syscall3
