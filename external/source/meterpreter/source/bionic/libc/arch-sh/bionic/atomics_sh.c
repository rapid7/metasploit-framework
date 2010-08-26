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

#include <pthread.h>
#include <linux/futex.h>

#define  SWAP_LOCK_COUNT  32U
static pthread_mutex_t  _swap_locks[SWAP_LOCK_COUNT];

#define  SWAP_LOCK(addr)   \
   &_swap_locks[((unsigned)(void *)(addr) >> 3U) % SWAP_LOCK_COUNT]

#if 0
/*
 * Only this function is moved to atomic_cmpxchg.S, and
 * implemented with gUSA framework.
 */
int __atomic_cmpxchg(int old, int _new, volatile int *ptr)
{
    int result;
    pthread_mutex_t *lock = SWAP_LOCK(ptr);

    pthread_mutex_lock(lock);

    if (*ptr == old) {
        *ptr  = _new;
        result = 0;
    } else {
        result = 1;
    }
    pthread_mutex_unlock(lock);
    return result;
}
#else
extern int __atomic_cmpxchg(int old, int _new, volatile int *ptr);
#endif

int __atomic_swap(int _new, volatile int *ptr)
{
    int oldValue;
    do {
        oldValue = *ptr;
    } while (__atomic_cmpxchg(oldValue, _new, ptr));
    return oldValue;
}

int __atomic_dec(volatile int *ptr)
{
    int oldValue;
    do {
        oldValue = *ptr;
    } while (__atomic_cmpxchg(oldValue, oldValue-1, ptr));
    return oldValue;
}

int __atomic_inc(volatile int *ptr)
{
    int32_t oldValue;
    do {
        oldValue = *ptr;
    } while (__atomic_cmpxchg(oldValue, oldValue+1, ptr));
    return oldValue;
}

extern int futex(volatile void *, int, int, void *, void *, int);

int __futex_wait(volatile void *ftx, int val, const struct timespec *timeout)
{
    return futex(ftx, FUTEX_WAIT, val, (void *)timeout, NULL, 0);
}

int __futex_wake(volatile void *ftx, int count)
{
    return futex(ftx, FUTEX_WAKE, count, NULL, NULL, 0);
}

int __futex_syscall3(volatile void *ftx, int op, int val)
{
    return futex(ftx, op, val, NULL, NULL, 0);
}

int __futex_syscall4(volative void *ftx, int op, int val, const struct timespec *timeout)
{
    return futex(ftx, op, val, (void *)timeout, NULL, 0);
}
