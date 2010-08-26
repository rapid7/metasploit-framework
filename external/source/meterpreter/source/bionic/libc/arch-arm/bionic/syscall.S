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


	.text
	.align 4
	.type syscall,#function
	.globl syscall
 
	.text
	.align

#if __ARM_EABI__

syscall:
    mov     ip, sp
    stmfd	sp!, {r4, r5, r6, r7}
    mov     r7, r0
    mov     r0, r1
    mov     r1, r2
    mov     r2, r3
    ldmfd	ip, {r3, r4, r5, r6}
    swi     #0
    ldmfd   sp!, {r4, r5, r6, r7}
    movs    r0, r0
    bxpl    lr
    b       __set_syscall_errno

#else

#ifndef __NR_syscall
#define __NR_syscall    113
#endif

syscall:
    stmfd   sp!, {r4, r5, lr}
    ldr     r4, [sp, #12]
    ldr     r5, [sp, #16]
    swi     __NR_syscall
    ldmfd   sp!, {r4, r5, lr}
    movs    r0, r0
    bxpl    lr
    b       __set_syscall_errno

#endif
