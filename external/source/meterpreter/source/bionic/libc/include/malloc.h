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
#ifndef _MALLOC_H_
#define _MALLOC_H_

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

extern __mallocfunc void*  malloc(size_t);
extern __mallocfunc void*  calloc(size_t, size_t);
extern __mallocfunc void*  realloc(void *ptr, size_t);
extern                void   free(void *);

extern void*   memalign(size_t  alignment, size_t  bytesize);
extern void*   valloc(size_t  bytesize);
extern void*   pvalloc(size_t  bytesize);
extern int     mallopt(int  param_number, int  param_value);
extern size_t  malloc_footprint(void);
extern size_t  malloc_max_footprint(void);

struct mallinfo {
    size_t arena;    /* non-mmapped space allocated from system */
    size_t ordblks;  /* number of free chunks */
    size_t smblks;   /* always 0 */
    size_t hblks;    /* always 0 */
    size_t hblkhd;   /* space in mmapped regions */
    size_t usmblks;  /* maximum total allocated space */
    size_t fsmblks;  /* always 0 */
    size_t uordblks; /* total allocated space */
    size_t fordblks; /* total free space */
    size_t keepcost; /* releasable (via malloc_trim) space */
};

extern struct mallinfo  mallinfo(void);


/*
  malloc_usable_size(void* p);

  Returns the number of bytes you can actually use in
  an allocated chunk, which may be more than you requested (although
  often not) due to alignment and minimum size constraints.
  You can use this many bytes without worrying about
  overwriting other allocated objects. This is not a particularly great
  programming practice. malloc_usable_size can be more useful in
  debugging and assertions, for example:

  p = malloc(n);
  assert(malloc_usable_size(p) >= 256);
*/
extern size_t malloc_usable_size(void*  block);

/*
  malloc_stats();
  Prints on stderr the amount of space obtained from the system (both
  via sbrk and mmap), the maximum amount (which may be more than
  current if malloc_trim and/or munmap got called), and the current
  number of bytes allocated via malloc (or realloc, etc) but not yet
  freed. Note that this is the number of bytes allocated, not the
  number requested. It will be larger than the number requested
  because of alignment and bookkeeping overhead. Because it includes
  alignment wastage as being in use, this figure may be greater than
  zero even when no user-level chunks are allocated.

  The reported current and maximum system memory can be inaccurate if
  a program makes other calls to system memory allocation functions
  (normally sbrk) outside of malloc.

  malloc_stats prints only the most commonly interesting statistics.
  More information can be obtained by calling mallinfo.
*/
extern void  malloc_stats(void);

__END_DECLS

#endif /* _MALLOC_H_ */

