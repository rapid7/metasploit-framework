/*
 * Copyright (C) 2009 The Android Open Source Project
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

.text
.type   __pthread_clone, @function
.globl  __pthread_clone
.align  4

__pthread_clone:
    /* insert the args onto the new stack */
    mov     r5, r0
    mov.l   r4, @-r0    /* func */
    mov.l   r7, @-r0    /* arg */

    /* do the system call */
    mov     r6, r4      /* Set clone_flags. new sp is ready in r5. */
    mov.l   0f, r3
    trapa   #(4 + 0x10)

    /* check error */
    cmp/pz  r0
    bf      __error

    /* check if parent or child */
    cmp/pl  r0
    bt      __return

    /* prepare args for __thread_entry */
    mov     #8, r1
    sub     r1, r15     /* -8 */
    mov.l   @r15+, r5   /* +4 */ /* arg */
    mov.l   @r15+, r4   /* +4 */ /* func */
    mov     r15, r6              /* tls */

    /* jump to __thread_entry */
    mov.l   1f, r0
    jmp @r0
    nop

__error:
    mov     #-1, r0
__return:
    rts
    nop

    .align 2
0:  .long   __NR_clone
1:  .long   __thread_entry

/* XXX: TODO: Add __bionic_clone here
 *            See bionic/bionic_clone.c and arch-arm/bionic/clone.S
 *            for more details...
 */