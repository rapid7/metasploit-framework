/*
 * Copyright (C) 2008-2010 The Android Open Source Project
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
    .type __pthread_clone, #function
    .global __pthread_clone
    .align 4
    .fnstart

__pthread_clone:
    @ insert the args onto the new stack
    str     r0, [r1, #-4]
    str     r3, [r1, #-8]

    @ do the system call
    @ get flags

    mov     r0, r2

    @ new sp is already in r1

#if __ARM_EABI__
    stmfd   sp!, {r4, r7}
    ldr     r7, =__NR_clone
    swi     #0
#else
    swi     #__NR_clone
#endif

    movs    r0, r0
#if __ARM_EABI__
    ldmnefd sp!, {r4, r7}
#endif
    blt     __error
    bxne    lr


    @ pick the function arg and call address off the stack and jump
    @ to the C __thread_entry function which does some setup and then
    @ calls the thread's start function

    ldr     r0, [sp, #-4]
    ldr     r1, [sp, #-8]
    mov     r2, sp			@ __thread_entry needs the TLS pointer
    b       __thread_entry

__error:
    mov     r0, #-1
    bx      lr
    .fnend


    #
    # This function is defined as:
    #
    #   pid_t  __bionic_clone( int  flags, void *child_stack,
    #                          pid_t *pid, void *tls, pid_t *ctid,
    #                          int  (*fn)(void *), void* arg );
    #
    # NOTE: This is not the same signature than the GLibc
    #       __clone function here !! Placing 'fn' and 'arg'
    #       at the end of the parameter list makes the
    #       implementation much simpler.
    #
    .type __bionic_clone, #function
    .globl __bionic_clone
    .align 4
    .fnstart

__bionic_clone:
    mov     ip, sp
    .save   {r4, r5, r6, r7}

    # save registers to parent stack
    stmfd   sp!, {r4, r5, r6, r7}

    # load extra parameters
    ldmfd   ip, {r4, r5, r6}

    # store 'fn' and 'arg' to the child stack
    str     r5, [r1, #-4]
    str     r6, [r1, #-8]

    # system call
    ldr     r7, =__NR_clone
    swi     #0
    movs    r0, r0
    beq     1f

    # in parent, reload saved registers
    # then either exit or error
    #
    ldmfd   sp!, {r4, r5, r6, r7}
    bxne    lr
    b       __set_syscall_errno

1:  # in the child - pick arguments
    ldr    r0, [sp, #-4]
    ldr    r1, [sp, #-8]
    b      __bionic_clone_entry

    .fnend
