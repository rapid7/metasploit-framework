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
#ifndef _SYS_MMAN_H_
#define _SYS_MMAN_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <asm/mman.h>
#include <asm/page.h>

__BEGIN_DECLS

#ifndef MAP_ANON
#define MAP_ANON  MAP_ANONYMOUS
#endif

#define MAP_FAILED ((void *)-1)

#define MREMAP_MAYMOVE  1
#define MREMAP_FIXED    2

extern void*  mmap(void *, size_t, int, int, int, off_t);
extern int    munmap(void *, size_t);
extern int    msync(const void *, size_t, int);
extern int    mprotect(const void *, size_t, int);
extern void*  mremap(void *, size_t, size_t, unsigned long);

extern int    mlockall(int);
extern int    munlockall(void);
extern int    mlock(const void *, size_t);
extern int    munlock(const void *, size_t);
extern int    madvise(const void *, size_t, int);

extern int    mlock(const void *addr, size_t len);
extern int    munlock(const void *addr, size_t len);

extern int    mincore(void*  start, size_t  length, unsigned char*  vec);

__END_DECLS

#endif /* _SYS_MMAN_H_ */
