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
#include <sys/select.h>
#include <signal.h>
#include <pthread.h>

int
pselect(int  n, fd_set*  readfds, fd_set*  writefds, fd_set*  errfds,
        const struct timespec*  timeout, const sigset_t*  sigmask)
{
    sigset_t        oldmask;
    int             result;
    struct timeval  tv, *tv_timeout = NULL;

    if (sigmask != NULL)
        pthread_sigmask( SIG_SETMASK, sigmask, &oldmask );

    if (timeout != NULL) {
        tv_timeout = &tv;
        tv.tv_sec  = timeout->tv_sec;
        tv.tv_usec = (timeout->tv_nsec + 999)/1000;  // round up
        if (tv.tv_usec >= 1000000) {
            tv.tv_sec  += 1;
            tv.tv_usec -= 1000000;
        }
    }

    result = select( n, readfds, writefds, errfds, tv_timeout );

    if (sigmask != NULL)
        pthread_sigmask( SIG_SETMASK, &oldmask, NULL );

    return result;
}
