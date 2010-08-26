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
.type syscall, @function
.globl syscall
.align 4

/*
 * Current implementation assumes that the all syscall
 * has maximum 7 arguments.
 */
syscall:
    /* get args */
    mov     r4, r3      /* system call number */
    mov     r5, r4
    mov     r6, r5
    mov     r7, r6
    mov.l   @r15, r7
    mov.l   @(4, r15), r0
    mov.l   @(8, r15), r1
    mov.l   @(12, r15), r2

    /* invoke trap */
    trapa   #(7 + 0x10) /* assuming 7 arguments */

    /* check return value */
    cmp/pz  r0
    bt      end

    /* keep error number */
    mov.l   r0, @-r15
    mov.l   0f, r1
    jsr     @r1
    mov     r0, r4
    mov.l   @r15+, r0

end:
    rts
    nop

    .align  2
0:  .long   __set_errno
