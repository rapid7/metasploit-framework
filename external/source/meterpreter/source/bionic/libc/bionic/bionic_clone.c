/*
 * Copyright (C) 2010 The Android Open Source Project
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
#define __GNU_SOURCE 1
#include <sched.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

/* WARNING: AT THE MOMENT, THIS IS ONLY SUPPORTED ON ARM
 */

extern int  __bionic_clone(unsigned long   clone_flags,
                           void*           newsp,
                           int            *parent_tidptr,
                           void           *new_tls,
                           int            *child_tidptr,
                           int            (*fn)(void *),
                           void          *arg);

extern void _exit_thread(int  retCode);

/* this function is called from the __bionic_clone
 * assembly fragment to call the thread function
 * then exit. */
extern void
__bionic_clone_entry( int (*fn)(void *), void *arg )
{
    int  ret = (*fn)(arg);
    _exit_thread(ret);
}

int
clone(int (*fn)(void *), void *child_stack, int flags, void*  arg, ...)
{
    va_list  args;
    int     *parent_tidptr = NULL;
    void    *new_tls = NULL;
    int     *child_tidptr = NULL;
    int     ret;

    /* extract optional parameters - they are cummulative */
    va_start(args, arg);
    if (flags & (CLONE_PARENT_SETTID|CLONE_SETTLS|CLONE_CHILD_SETTID)) {
        parent_tidptr = va_arg(args, int*);
    }
    if (flags & (CLONE_SETTLS|CLONE_CHILD_SETTID)) {
        new_tls = va_arg(args, void*);
    }
    if (flags & CLONE_CHILD_SETTID) {
        child_tidptr = va_arg(args, int*);
    }
    va_end(args);

    ret = __bionic_clone(flags, child_stack, parent_tidptr, new_tls, child_tidptr, fn, arg);
    return ret;
}
