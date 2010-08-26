/*
 * Copyright (C) 2009-2010 The Android Open Source Project
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
.align  4
.type   _start,#function
.globl  _start

# this is the small startup code that is first run when
# any executable that is statically-linked with Bionic
# runs.
#
# it's purpose is to call __libc_init with appropriate
# arguments, which are:
#
#    - the address of the raw data block setup by the Linux
#      kernel ELF loader
#
#    - address of an "onexit" function, not used on any
#      platform supported by Bionic
#
#    - address of the "main" function of the program. We
#      can't hard-code it in the adr pseudo instruction
#      so we use a tiny trampoline that will get relocated
#      by the dynamic linker before this code runs
#
#    - address of the constructor list
#
_start:
    mov     r15, r4
    mov     #0, r5
    mov.l   0f, r6
    mova    2f, r0
    mov     r0, r7
    mov.l   1f, r0
    jmp     @r0
    nop

    .balign 4
0:  .long   main
1:  .long   __libc_init
2:  .long   __PREINIT_ARRAY__
    .long   __INIT_ARRAY__
    .long   __FINI_ARRAY__
    .long   __CTOR_LIST__

    .section .preinit_array, "aw"
    .globl __PREINIT_ARRAY__
__PREINIT_ARRAY__:
    .long -1

    .section .init_array, "aw"
    .globl __INIT_ARRAY__
__INIT_ARRAY__:
    .long -1

    .section .fini_array, "aw"
    .globl __FINI_ARRAY__
__FINI_ARRAY__:
    .long -1

    .section .ctors, "aw"
    .globl __CTOR_LIST__
__CTOR_LIST__:
    .long -1

#include "__dso_handle.S"
