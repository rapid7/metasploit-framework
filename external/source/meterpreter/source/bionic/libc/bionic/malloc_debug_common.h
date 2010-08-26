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

/*
 * Contains declarations of types and constants used by malloc leak
 * detection code in both, libc and libc_malloc_debug libraries.
 */
#ifndef MALLOC_DEBUG_COMMON_H
#define MALLOC_DEBUG_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#define HASHTABLE_SIZE      1543
#define BACKTRACE_SIZE      32
/* flag definitions, currently sharing storage with "size" */
#define SIZE_FLAG_ZYGOTE_CHILD  (1<<31)
#define SIZE_FLAG_MASK          (SIZE_FLAG_ZYGOTE_CHILD)

#define MAX_SIZE_T           (~(size_t)0)

// =============================================================================
// Structures
// =============================================================================

typedef struct HashEntry HashEntry;
struct HashEntry {
    size_t slot;
    HashEntry* prev;
    HashEntry* next;
    size_t numEntries;
    // fields above "size" are NOT sent to the host
    size_t size;
    size_t allocations;
    intptr_t backtrace[0];
};

typedef struct HashTable HashTable;
struct HashTable {
    size_t count;
    HashEntry* slots[HASHTABLE_SIZE];
};

/* Entry in malloc dispatch table. */
typedef struct MallocDebug MallocDebug;
struct MallocDebug {
    /* Address of the actual malloc routine. */
    void* (*malloc)(size_t bytes);
    /* Address of the actual free routine. */
    void  (*free)(void* mem);
    /* Address of the actual calloc routine. */
    void* (*calloc)(size_t n_elements, size_t elem_size);
    /* Address of the actual realloc routine. */
    void* (*realloc)(void* oldMem, size_t bytes);
    /* Address of the actual memalign routine. */
    void* (*memalign)(size_t alignment, size_t bytes);
};

/* Malloc debugging initialization routine.
 * This routine must be implemented in .so modules that implement malloc
 * debugging. This routine is called once per process from malloc_init_impl
 * routine implemented in bionic/libc/bionic/malloc_debug_common.c when malloc
 * debugging gets initialized for the process.
 * Return:
 *  0 on success, -1 on failure.
 */
typedef int (*MallocDebugInit)(void);

#ifdef __cplusplus
};  /* end of extern "C" */
#endif

#endif  // MALLOC_DEBUG_COMMON_H
