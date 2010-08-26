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
#include <pthread.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unwind.h>
#include <dlfcn.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/system_properties.h>

#include "dlmalloc.h"
#include "logd.h"
#include "malloc_debug_common.h"

// This file should be included into the build only when
// MALLOC_LEAK_CHECK, or MALLOC_QEMU_INSTRUMENT, or both
// macros are defined.
#ifndef MALLOC_LEAK_CHECK
#error MALLOC_LEAK_CHECK is not defined.
#endif  // !MALLOC_LEAK_CHECK

// Global variables defined in malloc_debug_common.c
extern int gMallocLeakZygoteChild;
extern pthread_mutex_t gAllocationsMutex;
extern HashTable gHashTable;
extern const MallocDebug __libc_malloc_default_dispatch;
extern const MallocDebug* __libc_malloc_dispatch;

// =============================================================================
// log functions
// =============================================================================

#define debug_log(format, ...)  \
    __libc_android_log_print(ANDROID_LOG_DEBUG, "malloc_leak_check", (format), ##__VA_ARGS__ )
#define error_log(format, ...)  \
    __libc_android_log_print(ANDROID_LOG_ERROR, "malloc_leak_check", (format), ##__VA_ARGS__ )
#define info_log(format, ...)  \
    __libc_android_log_print(ANDROID_LOG_INFO, "malloc_leak_check", (format), ##__VA_ARGS__ )

static int gTrapOnError = 1;

#define MALLOC_ALIGNMENT    8
#define GUARD               0x48151642
#define DEBUG               0

// =============================================================================
// Structures
// =============================================================================
typedef struct AllocationEntry AllocationEntry;
struct AllocationEntry {
    HashEntry* entry;
    uint32_t guard;
};


// =============================================================================
// Hash Table functions
// =============================================================================
static uint32_t get_hash(intptr_t* backtrace, size_t numEntries)
{
    if (backtrace == NULL) return 0;

    int hash = 0;
    size_t i;
    for (i = 0 ; i < numEntries ; i++) {
        hash = (hash * 33) + (backtrace[i] >> 2);
    }

    return hash;
}

static HashEntry* find_entry(HashTable* table, int slot,
        intptr_t* backtrace, size_t numEntries, size_t size)
{
    HashEntry* entry = table->slots[slot];
    while (entry != NULL) {
        //debug_log("backtrace: %p, entry: %p entry->backtrace: %p\n",
        //        backtrace, entry, (entry != NULL) ? entry->backtrace : NULL);
        /*
         * See if the entry matches exactly.  We compare the "size" field,
         * including the flag bits.
         */
        if (entry->size == size && entry->numEntries == numEntries &&
                !memcmp(backtrace, entry->backtrace, numEntries * sizeof(intptr_t))) {
            return entry;
        }

        entry = entry->next;
    }

    return NULL;
}

static HashEntry* record_backtrace(intptr_t* backtrace, size_t numEntries, size_t size)
{
    size_t hash = get_hash(backtrace, numEntries);
    size_t slot = hash % HASHTABLE_SIZE;

    if (size & SIZE_FLAG_MASK) {
        debug_log("malloc_debug: allocation %zx exceeds bit width\n", size);
        abort();
    }

    if (gMallocLeakZygoteChild)
        size |= SIZE_FLAG_ZYGOTE_CHILD;

    HashEntry* entry = find_entry(&gHashTable, slot, backtrace, numEntries, size);

    if (entry != NULL) {
        entry->allocations++;
    } else {
        // create a new entry
        entry = (HashEntry*)dlmalloc(sizeof(HashEntry) + numEntries*sizeof(intptr_t));
        if (!entry)
            return NULL;
        entry->allocations = 1;
        entry->slot = slot;
        entry->prev = NULL;
        entry->next = gHashTable.slots[slot];
        entry->numEntries = numEntries;
        entry->size = size;

        memcpy(entry->backtrace, backtrace, numEntries * sizeof(intptr_t));

        gHashTable.slots[slot] = entry;

        if (entry->next != NULL) {
            entry->next->prev = entry;
        }

        // we just added an entry, increase the size of the hashtable
        gHashTable.count++;
    }

    return entry;
}

static int is_valid_entry(HashEntry* entry)
{
    if (entry != NULL) {
        int i;
        for (i = 0 ; i < HASHTABLE_SIZE ; i++) {
            HashEntry* e1 = gHashTable.slots[i];

            while (e1 != NULL) {
                if (e1 == entry) {
                    return 1;
                }

                e1 = e1->next;
            }
        }
    }

    return 0;
}

static void remove_entry(HashEntry* entry)
{
    HashEntry* prev = entry->prev;
    HashEntry* next = entry->next;

    if (prev != NULL) entry->prev->next = next;
    if (next != NULL) entry->next->prev = prev;

    if (prev == NULL) {
        // we are the head of the list. set the head to be next
        gHashTable.slots[entry->slot] = entry->next;
    }

    // we just removed and entry, decrease the size of the hashtable
    gHashTable.count--;
}


// =============================================================================
// stack trace functions
// =============================================================================

typedef struct
{
    size_t count;
    intptr_t* addrs;
} stack_crawl_state_t;


/* depends how the system includes define this */
#ifdef HAVE_UNWIND_CONTEXT_STRUCT
typedef struct _Unwind_Context __unwind_context;
#else
typedef _Unwind_Context __unwind_context;
#endif

static _Unwind_Reason_Code trace_function(__unwind_context *context, void *arg)
{
    stack_crawl_state_t* state = (stack_crawl_state_t*)arg;
    if (state->count) {
        intptr_t ip = (intptr_t)_Unwind_GetIP(context);
        if (ip) {
            state->addrs[0] = ip;
            state->addrs++;
            state->count--;
            return _URC_NO_REASON;
        }
    }
    /*
     * If we run out of space to record the address or 0 has been seen, stop
     * unwinding the stack.
     */
    return _URC_END_OF_STACK;
}

static inline
int get_backtrace(intptr_t* addrs, size_t max_entries)
{
    stack_crawl_state_t state;
    state.count = max_entries;
    state.addrs = (intptr_t*)addrs;
    _Unwind_Backtrace(trace_function, (void*)&state);
    return max_entries - state.count;
}

// =============================================================================
// malloc check functions
// =============================================================================

#define CHK_FILL_FREE           0xef
#define CHK_SENTINEL_VALUE      0xeb
#define CHK_SENTINEL_HEAD_SIZE  16
#define CHK_SENTINEL_TAIL_SIZE  16
#define CHK_OVERHEAD_SIZE       (   CHK_SENTINEL_HEAD_SIZE +    \
                                    CHK_SENTINEL_TAIL_SIZE +    \
                                    sizeof(size_t) )

static void dump_stack_trace()
{
    intptr_t addrs[20];
    int c = get_backtrace(addrs, 20);
    char buf[16];
    char tmp[16*20];
    int i;

    tmp[0] = 0; // Need to initialize tmp[0] for the first strcat
    for (i=0 ; i<c; i++) {
        snprintf(buf, sizeof buf, "%2d: %08x\n", i, addrs[i]);
        strlcat(tmp, buf, sizeof tmp);
    }
    __libc_android_log_print(ANDROID_LOG_ERROR, "libc", "call stack:\n%s", tmp);
}

static int is_valid_malloc_pointer(void* addr)
{
    return 1;
}

static void assert_log_message(const char* format, ...)
{
    va_list  args;

    pthread_mutex_lock(&gAllocationsMutex);
    {
        const MallocDebug* current_dispatch = __libc_malloc_dispatch;
        __libc_malloc_dispatch = &__libc_malloc_default_dispatch;
        va_start(args, format);
        __libc_android_log_vprint(ANDROID_LOG_ERROR, "libc",
                                format, args);
        va_end(args);
        dump_stack_trace();
        if (gTrapOnError) {
            __builtin_trap();
        }
        __libc_malloc_dispatch = current_dispatch;
    }
    pthread_mutex_unlock(&gAllocationsMutex);
}

static void assert_valid_malloc_pointer(void* mem)
{
    if (mem && !is_valid_malloc_pointer(mem)) {
        assert_log_message(
            "*** MALLOC CHECK: buffer %p, is not a valid "
            "malloc pointer (are you mixing up new/delete "
            "and malloc/free?)", mem);
    }
}

/* Check that a given address corresponds to a guarded block,
 * and returns its original allocation size in '*allocated'.
 * 'func' is the capitalized name of the caller function.
 * Returns 0 on success, or -1 on failure.
 * NOTE: Does not return if gTrapOnError is set.
 */
static int chk_mem_check(void*       mem,
                         size_t*     allocated,
                         const char* func)
{
    char*  buffer;
    size_t offset, bytes;
    int    i;
    char*  buf;

    /* first check the bytes in the sentinel header */
    buf = (char*)mem - CHK_SENTINEL_HEAD_SIZE;
    for (i=0 ; i<CHK_SENTINEL_HEAD_SIZE ; i++) {
        if (buf[i] != CHK_SENTINEL_VALUE) {
            assert_log_message(
                "*** %s CHECK: buffer %p "
                "corrupted %d bytes before allocation",
                func, mem, CHK_SENTINEL_HEAD_SIZE-i);
            return -1;
        }
    }

    /* then the ones in the sentinel trailer */
    buffer = (char*)mem - CHK_SENTINEL_HEAD_SIZE;
    offset = dlmalloc_usable_size(buffer) - sizeof(size_t);
    bytes  = *(size_t *)(buffer + offset);

    buf = (char*)mem + bytes;
    for (i=CHK_SENTINEL_TAIL_SIZE-1 ; i>=0 ; i--) {
        if (buf[i] != CHK_SENTINEL_VALUE) {
            assert_log_message(
                "*** %s CHECK: buffer %p, size=%lu, "
                "corrupted %d bytes after allocation",
                func, buffer, bytes, i+1);
            return -1;
        }
    }

    *allocated = bytes;
    return 0;
}


void* chk_malloc(size_t bytes)
{
    char* buffer = (char*)dlmalloc(bytes + CHK_OVERHEAD_SIZE);
    if (buffer) {
        memset(buffer, CHK_SENTINEL_VALUE, bytes + CHK_OVERHEAD_SIZE);
        size_t offset = dlmalloc_usable_size(buffer) - sizeof(size_t);
        *(size_t *)(buffer + offset) = bytes;
        buffer += CHK_SENTINEL_HEAD_SIZE;
    }
    return buffer;
}

void  chk_free(void* mem)
{
    assert_valid_malloc_pointer(mem);
    if (mem) {
        size_t  size;
        char*   buffer;

        if (chk_mem_check(mem, &size, "FREE") == 0) {
            buffer = (char*)mem - CHK_SENTINEL_HEAD_SIZE;
            memset(buffer, CHK_FILL_FREE, size + CHK_OVERHEAD_SIZE);
            dlfree(buffer);
        }
    }
}

void* chk_calloc(size_t n_elements, size_t elem_size)
{
    size_t  size;
    void*   ptr;

    /* Fail on overflow - just to be safe even though this code runs only
     * within the debugging C library, not the production one */
    if (n_elements && MAX_SIZE_T / n_elements < elem_size) {
        return NULL;
    }
    size = n_elements * elem_size;
    ptr  = chk_malloc(size);
    if (ptr != NULL) {
        memset(ptr, 0, size);
    }
    return ptr;
}

void* chk_realloc(void* mem, size_t bytes)
{
    char*   buffer;
    int     ret;
    size_t  old_bytes = 0;

    assert_valid_malloc_pointer(mem);

    if (mem != NULL && chk_mem_check(mem, &old_bytes, "REALLOC") < 0)
        return NULL;

    char* new_buffer = chk_malloc(bytes);
    if (mem == NULL) {
        return new_buffer;
    }

    if (new_buffer) {
        if (bytes > old_bytes)
            bytes = old_bytes;
        memcpy(new_buffer, mem, bytes);
        chk_free(mem);
    }

    return new_buffer;
}

void* chk_memalign(size_t alignment, size_t bytes)
{
    // XXX: it's better to use malloc, than being wrong
    return chk_malloc(bytes);
}

// =============================================================================
// malloc fill functions
// =============================================================================

void* fill_malloc(size_t bytes)
{
    void* buffer = dlmalloc(bytes);
    if (buffer) {
        memset(buffer, CHK_SENTINEL_VALUE, bytes);
    }
    return buffer;
}

void  fill_free(void* mem)
{
    size_t bytes = dlmalloc_usable_size(mem);
    memset(mem, CHK_FILL_FREE, bytes);
    dlfree(mem);
}

void* fill_realloc(void* mem, size_t bytes)
{
    void* buffer = fill_malloc(bytes);
    if (mem == NULL) {
        return buffer;
    }
    if (buffer) {
        size_t old_size = dlmalloc_usable_size(mem);
        size_t size = (bytes < old_size)?(bytes):(old_size);
        memcpy(buffer, mem, size);
        fill_free(mem);
    }
    return buffer;
}

void* fill_memalign(size_t alignment, size_t bytes)
{
    void* buffer = dlmemalign(alignment, bytes);
    if (buffer) {
        memset(buffer, CHK_SENTINEL_VALUE, bytes);
    }
    return buffer;
}

// =============================================================================
// malloc leak functions
// =============================================================================

#define MEMALIGN_GUARD  ((void*)0xA1A41520)

void* leak_malloc(size_t bytes)
{
    // allocate enough space infront of the allocation to store the pointer for
    // the alloc structure. This will making free'ing the structer really fast!

    // 1. allocate enough memory and include our header
    // 2. set the base pointer to be right after our header

    void* base = dlmalloc(bytes + sizeof(AllocationEntry));
    if (base != NULL) {
        pthread_mutex_lock(&gAllocationsMutex);

            intptr_t backtrace[BACKTRACE_SIZE];
            size_t numEntries = get_backtrace(backtrace, BACKTRACE_SIZE);

            AllocationEntry* header = (AllocationEntry*)base;
            header->entry = record_backtrace(backtrace, numEntries, bytes);
            header->guard = GUARD;

            // now increment base to point to after our header.
            // this should just work since our header is 8 bytes.
            base = (AllocationEntry*)base + 1;

        pthread_mutex_unlock(&gAllocationsMutex);
    }

    return base;
}

void leak_free(void* mem)
{
    if (mem != NULL) {
        pthread_mutex_lock(&gAllocationsMutex);

        // check the guard to make sure it is valid
        AllocationEntry* header = (AllocationEntry*)mem - 1;

        if (header->guard != GUARD) {
            // could be a memaligned block
            if (((void**)mem)[-1] == MEMALIGN_GUARD) {
                mem = ((void**)mem)[-2];
                header = (AllocationEntry*)mem - 1;
            }
        }

        if (header->guard == GUARD || is_valid_entry(header->entry)) {
            // decrement the allocations
            HashEntry* entry = header->entry;
            entry->allocations--;
            if (entry->allocations <= 0) {
                remove_entry(entry);
                dlfree(entry);
            }

            // now free the memory!
            dlfree(header);
        } else {
            debug_log("WARNING bad header guard: '0x%x'! and invalid entry: %p\n",
                    header->guard, header->entry);
        }

        pthread_mutex_unlock(&gAllocationsMutex);
    }
}

void* leak_calloc(size_t n_elements, size_t elem_size)
{
    size_t  size;
    void*   ptr;

    /* Fail on overflow - just to be safe even though this code runs only
     * within the debugging C library, not the production one */
    if (n_elements && MAX_SIZE_T / n_elements < elem_size) {
        return NULL;
    }
    size = n_elements * elem_size;
    ptr  = leak_malloc(size);
    if (ptr != NULL) {
        memset(ptr, 0, size);
    }
    return ptr;
}

void* leak_realloc(void* oldMem, size_t bytes)
{
    if (oldMem == NULL) {
        return leak_malloc(bytes);
    }
    void* newMem = NULL;
    AllocationEntry* header = (AllocationEntry*)oldMem - 1;
    if (header && header->guard == GUARD) {
        size_t oldSize = header->entry->size & ~SIZE_FLAG_MASK;
        newMem = leak_malloc(bytes);
        if (newMem != NULL) {
            size_t copySize = (oldSize <= bytes) ? oldSize : bytes;
            memcpy(newMem, oldMem, copySize);
            leak_free(oldMem);
        }
    } else {
        newMem = dlrealloc(oldMem, bytes);
    }
    return newMem;
}

void* leak_memalign(size_t alignment, size_t bytes)
{
    // we can just use malloc
    if (alignment <= MALLOC_ALIGNMENT)
        return leak_malloc(bytes);

    // need to make sure it's a power of two
    if (alignment & (alignment-1))
        alignment = 1L << (31 - __builtin_clz(alignment));

    // here, aligment is at least MALLOC_ALIGNMENT<<1 bytes
    // we will align by at least MALLOC_ALIGNMENT bytes
    // and at most alignment-MALLOC_ALIGNMENT bytes
    size_t size = (alignment-MALLOC_ALIGNMENT) + bytes;
    void* base = leak_malloc(size);
    if (base != NULL) {
        intptr_t ptr = (intptr_t)base;
        if ((ptr % alignment) == 0)
            return base;

        // align the pointer
        ptr += ((-ptr) % alignment);

        // there is always enough space for the base pointer and the guard
        ((void**)ptr)[-1] = MEMALIGN_GUARD;
        ((void**)ptr)[-2] = base;

        return (void*)ptr;
    }
    return base;
}

/* Initializes malloc debugging framework.
 * See comments on MallocDebugInit in malloc_debug_common.h
 */
int malloc_debug_initialize(void)
{
    // We don't really have anything that requires initialization here.
    return 0;
}
