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
#include <sys/atomics.h>

#define FUTEX_SYSCALL 240
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

int __futex_wait(volatile void *ftx, int val)
{
    int ret;
    asm volatile (
        "int $0x80;"
        : "=a" (ret)
        : "0" (FUTEX_SYSCALL),
          "b" (ftx),
          "c" (FUTEX_WAIT),
          "d" (val),
          "S" (0)
    );
    return ret;
}

int __futex_wake(volatile void *ftx, int count)
{
    int ret;
    asm volatile (
        "int $0x80;"
        : "=a" (ret)
        : "0" (FUTEX_SYSCALL),
          "b" (ftx),
          "c" (FUTEX_WAKE),
          "d" (count)
    );
    return ret;
}

int __atomic_cmpxchg(int old, int new, volatile int* addr) {
    int xchg;
    asm volatile (
        "lock;"
        "cmpxchg %%ecx, (%%edx);"
        "setne %%al;"
        : "=a" (xchg)
        : "a" (old),
          "c" (new),
          "d" (addr)
    );
    return xchg;
}

int __atomic_swap(int new, volatile int* addr) {
    int old;
    asm volatile (
        "lock;"
        "xchg %%ecx, (%%edx);"
        : "=c" (old)
        : "c" (new),
          "d" (addr)
    );
    return old;
}

int __atomic_dec(volatile int* addr) {
    int old;
    do {
        old = *addr;
    } while (atomic_cmpxchg(old, old-1, addr));
    return old;
}
