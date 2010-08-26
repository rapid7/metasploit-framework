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
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>

int __rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo, const struct timespec *uts, size_t sigsetsize);

/* ok, this is really subtle: <asm/signal.h> defines sigset_t differently
 * when you're in the kernel or in the C library.
 *
 * in the kernel, this is an array of 2 32-bit unsigned longs
 * in the C library, this is a single 32-bit unsigned long
 *
 * moreover, the kernel implementation of rt_sigtimedwait doesn't
 * accept anything except kernel-sized signal sets (probably a bug !)
 *
 * we thus need to create a fake kernel sigset !!
 */

int sigwait(const sigset_t *set, int *sig)
{
    int  ret;
    /* use a union to get rid of aliasing warnings */
    union {
      unsigned long  kernel_sigset[2];
      sigset_t       dummy_sigset;
    } u;

    u.kernel_sigset[0] = *set;
    u.kernel_sigset[1] = 0;  /* no real-time signals supported ? */
    for (;;)
    {
     /* __rt_sigtimedwait can return EAGAIN or EINTR, we need to loop
      * around them since sigwait is only allowed to return EINVAL
      */
      ret = __rt_sigtimedwait ( &u.dummy_sigset, NULL, NULL, sizeof(u.kernel_sigset));
      if (ret >= 0)
        break;

      if (errno != EAGAIN && errno != EINTR)
        return errno;
    }

    *sig = ret;
    return 0;
}

