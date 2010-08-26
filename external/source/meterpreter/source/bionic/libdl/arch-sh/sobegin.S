/*
 * Copyright (C) 2009 The Android Open Project
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
    .text
    .align 4
    .type  _init,#function
    .globl _init

# The toolchain for SH-Linux does not produce INIT_ARRAY information which
# bionic linker relies on.  Instead of it, The toolchain for SH-Linux produces
# INIT information when it find the function whose name is '_init'.
#
_init:
    sts.l   pr, @-r15
    mov.l   r8, @-r15
    mov.l   0f, r8      /* first entry is invalid */
.L_loop:
    add     #4, r8
    mov.l   @r8, r0
    cmp/eq  #0, r0      /* Zero terimnated. See 'soend.so'. */
    bt      .L_end
    jsr     @r0         /* invoke a constructor */
    nop
    bra     .L_loop
    nop
.L_end:
    mov.l   @r15+, r8
    lds.l   @r15+, pr

    rts
    nop

    .balign 4
0:  .long   __CTOR_LIST__

# the .ctors section contains a list of pointers to "constructor"
# functions that need to be called in order during C library initialization,
# just before the program is being run. This is a C++ requirement
#
# the last entry shall be 0, and is defined in crtend.S
#
    .section .ctors, "aw"
    .globl __CTOR_LIST__
__CTOR_LIST__:
    .long   -1

