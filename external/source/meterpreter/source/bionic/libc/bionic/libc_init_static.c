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
/*
 * libc_init_static.c
 *
 * The program startup function __libc_init() defined here is
 * used for static executables only (i.e. those that don't depend
 * on shared libraries). It is called from arch-$ARCH/bionic/crtbegin_static.S
 * which is directly invoked by the kernel when the program is launched.
 *
 * The 'structors' parameter contains pointers to various initializer
 * arrays that must be run before the program's 'main' routine is launched.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <elf.h>
#include "pthread_internal.h"
#include "atexit.h"
#include "libc_init_common.h"

#include <bionic_tls.h>
#include <errno.h>

static void call_array(void(**list)())
{
    // First element is -1, list is null-terminated
    while (*++list) {
        (*list)();
    }
}

__noreturn void __libc_init(uintptr_t *elfdata,
                       void (*onexit)(void),
                       int (*slingshot)(int, char**, char**),
                       structors_array_t const * const structors)
{
    int  argc;
    char **argv, **envp;

    /* Initialize the C runtime environment */
    __libc_init_common(elfdata);

    /* Several Linux ABIs don't pass the onexit pointer, and the ones that
     * do never use it.  Therefore, we ignore it.
     */

    /* pre-init array. */
    call_array(structors->preinit_array);

    /* .ctors section initializers, for non-arm-eabi ABIs */
    call_array(structors->ctors_array);

    // call static constructors
    call_array(structors->init_array);

    argc = (int) *elfdata;
    argv = (char**)(elfdata + 1);
    envp = argv + argc + 1;

    exit(slingshot(argc, argv, envp));
}
