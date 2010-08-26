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
 * Contains definition of structures, global variables, and implementation of
 * routines that are used by malloc leak detection code and other components in
 * the system. The trick is that some components expect these data and
 * routines to be defined / implemented in libc.so library, regardless
 * whether or not MALLOC_LEAK_CHECK macro is defined. To make things even
 * more tricky, malloc leak detection code, implemented in
 * libc_malloc_debug.so also requires access to these variables and routines
 * (to fill allocation entry hash table, for example). So, all relevant
 * variables and routines are defined / implemented here and exported
 * to all, leak detection code and other components via dynamic (libc.so),
 * or static (libc.a) linking.
 */

#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "dlmalloc.h"
#include "malloc_debug_common.h"

/*
 * In a VM process, this is set to 1 after fork()ing out of zygote.
 */
int gMallocLeakZygoteChild = 0;

pthread_mutex_t gAllocationsMutex = PTHREAD_MUTEX_INITIALIZER;
HashTable gHashTable;

// =============================================================================
// output functions
// =============================================================================

static int hash_entry_compare(const void* arg1, const void* arg2)
{
    HashEntry* e1 = *(HashEntry**)arg1;
    HashEntry* e2 = *(HashEntry**)arg2;

    size_t nbAlloc1 = e1->allocations;
    size_t nbAlloc2 = e2->allocations;
    size_t size1 = e1->size & ~SIZE_FLAG_MASK;
    size_t size2 = e2->size & ~SIZE_FLAG_MASK;
    size_t alloc1 = nbAlloc1 * size1;
    size_t alloc2 = nbAlloc2 * size2;

    // sort in descending order by:
    // 1) total size
    // 2) number of allocations
    //
    // This is used for sorting, not determination of equality, so we don't
    // need to compare the bit flags.
    int result;
    if (alloc1 > alloc2) {
        result = -1;
    } else if (alloc1 < alloc2) {
        result = 1;
    } else {
        if (nbAlloc1 > nbAlloc2) {
            result = -1;
        } else if (nbAlloc1 < nbAlloc2) {
            result = 1;
        } else {
            result = 0;
        }
    }
    return result;
}

/*
 * Retrieve native heap information.
 *
 * "*info" is set to a buffer we allocate
 * "*overallSize" is set to the size of the "info" buffer
 * "*infoSize" is set to the size of a single entry
 * "*totalMemory" is set to the sum of all allocations we're tracking; does
 *   not include heap overhead
 * "*backtraceSize" is set to the maximum number of entries in the back trace
 */
void get_malloc_leak_info(uint8_t** info, size_t* overallSize,
        size_t* infoSize, size_t* totalMemory, size_t* backtraceSize)
{
    // don't do anything if we have invalid arguments
    if (info == NULL || overallSize == NULL || infoSize == NULL ||
            totalMemory == NULL || backtraceSize == NULL) {
        return;
    }

    pthread_mutex_lock(&gAllocationsMutex);

    if (gHashTable.count == 0) {
        *info = NULL;
        *overallSize = 0;
        *infoSize = 0;
        *totalMemory = 0;
        *backtraceSize = 0;
        goto done;
    }

    void** list = (void**)dlmalloc(sizeof(void*) * gHashTable.count);

    // get the entries into an array to be sorted
    int index = 0;
    int i;
    for (i = 0 ; i < HASHTABLE_SIZE ; i++) {
        HashEntry* entry = gHashTable.slots[i];
        while (entry != NULL) {
            list[index] = entry;
            *totalMemory = *totalMemory +
                ((entry->size & ~SIZE_FLAG_MASK) * entry->allocations);
            index++;
            entry = entry->next;
        }
    }

    // XXX: the protocol doesn't allow variable size for the stack trace (yet)
    *infoSize = (sizeof(size_t) * 2) + (sizeof(intptr_t) * BACKTRACE_SIZE);
    *overallSize = *infoSize * gHashTable.count;
    *backtraceSize = BACKTRACE_SIZE;

    // now get A byte array big enough for this
    *info = (uint8_t*)dlmalloc(*overallSize);

    if (*info == NULL) {
        *overallSize = 0;
        goto out_nomem_info;
    }

    qsort((void*)list, gHashTable.count, sizeof(void*), hash_entry_compare);

    uint8_t* head = *info;
    const int count = gHashTable.count;
    for (i = 0 ; i < count ; i++) {
        HashEntry* entry = list[i];
        size_t entrySize = (sizeof(size_t) * 2) + (sizeof(intptr_t) * entry->numEntries);
        if (entrySize < *infoSize) {
            /* we're writing less than a full entry, clear out the rest */
            memset(head + entrySize, 0, *infoSize - entrySize);
        } else {
            /* make sure the amount we're copying doesn't exceed the limit */
            entrySize = *infoSize;
        }
        memcpy(head, &(entry->size), entrySize);
        head += *infoSize;
    }

out_nomem_info:
    dlfree(list);

done:
    pthread_mutex_unlock(&gAllocationsMutex);
}

void free_malloc_leak_info(uint8_t* info)
{
    dlfree(info);
}

struct mallinfo mallinfo()
{
    return dlmallinfo();
}

void* valloc(size_t bytes) {
    /* assume page size of 4096 bytes */
    return memalign( getpagesize(), bytes );
}

/* Support for malloc debugging.
 * Note that if USE_DL_PREFIX is not defined, it's assumed that memory
 * allocation routines are implemented somewhere else, so all our custom
 * malloc routines should not be compiled at all.
 */
#ifdef USE_DL_PREFIX

/* Table for dispatching malloc calls, initialized with default dispatchers. */
const MallocDebug __libc_malloc_default_dispatch __attribute__((aligned(32))) =
{
    dlmalloc, dlfree, dlcalloc, dlrealloc, dlmemalign
};

/* Selector of dispatch table to use for dispatching malloc calls. */
const MallocDebug* __libc_malloc_dispatch = &__libc_malloc_default_dispatch;

void* malloc(size_t bytes) {
    return __libc_malloc_dispatch->malloc(bytes);
}
void free(void* mem) {
    __libc_malloc_dispatch->free(mem);
}
void* calloc(size_t n_elements, size_t elem_size) {
    return __libc_malloc_dispatch->calloc(n_elements, elem_size);
}
void* realloc(void* oldMem, size_t bytes) {
    return __libc_malloc_dispatch->realloc(oldMem, bytes);
}
void* memalign(size_t alignment, size_t bytes) {
    return __libc_malloc_dispatch->memalign(alignment, bytes);
}

/* We implement malloc debugging only in libc.so, so code bellow
 * must be excluded if we compile this file for static libc.a
 */
#ifndef LIBC_STATIC
#include <sys/system_properties.h>
#include <dlfcn.h>
#include "logd.h"

// =============================================================================
// log functions
// =============================================================================

#define debug_log(format, ...)  \
   __libc_android_log_print(ANDROID_LOG_DEBUG, "libc", (format), ##__VA_ARGS__ )
#define error_log(format, ...)  \
   __libc_android_log_print(ANDROID_LOG_ERROR, "libc", (format), ##__VA_ARGS__ )
#define info_log(format, ...)  \
   __libc_android_log_print(ANDROID_LOG_INFO, "libc", (format), ##__VA_ARGS__ )

/* Table for dispatching malloc calls, depending on environment. */
static MallocDebug gMallocUse __attribute__((aligned(32))) = {
    dlmalloc, dlfree, dlcalloc, dlrealloc, dlmemalign
};

extern char*  __progname;

/* Handle to shared library where actual memory allocation is implemented.
 * This library is loaded and memory allocation calls are redirected there
 * when libc.debug.malloc environment variable contains value other than
 * zero:
 * 1  - For memory leak detections.
 * 5  - For filling allocated / freed memory with patterns defined by
 *      CHK_SENTINEL_VALUE, and CHK_FILL_FREE macros.
 * 10 - For adding pre-, and post- allocation stubs in order to detect
 *      buffer overruns.
 * Note that emulator's memory allocation instrumentation is not controlled by
 * libc.debug.malloc value, but rather by emulator, started with -memcheck
 * option. Note also, that if emulator has started with -memcheck option,
 * emulator's instrumented memory allocation will take over value saved in
 * libc.debug.malloc. In other words, if emulator has started with -memcheck
 * option, libc.debug.malloc value is ignored.
 * Actual functionality for debug levels 1-10 is implemented in
 * libc_malloc_debug_leak.so, while functionality for emultor's instrumented
 * allocations is implemented in libc_malloc_debug_qemu.so and can be run inside
  * the emulator only.
 */
static void* libc_malloc_impl_handle = NULL;

/* Make sure we have MALLOC_ALIGNMENT that matches the one that is
 * used in dlmalloc. Emulator's memchecker needs this value to properly
 * align its guarding zones.
 */
#ifndef MALLOC_ALIGNMENT
#define MALLOC_ALIGNMENT ((size_t)8U)
#endif  /* MALLOC_ALIGNMENT */

/* Initializes memory allocation framework once per process. */
static void malloc_init_impl(void)
{
    const char* so_name = NULL;
    MallocDebugInit malloc_debug_initialize = NULL;
    unsigned int qemu_running = 0;
    unsigned int debug_level = 0;
    unsigned int memcheck_enabled = 0;
    char env[PROP_VALUE_MAX];
    char memcheck_tracing[PROP_VALUE_MAX];

    /* Get custom malloc debug level. Note that emulator started with
     * memory checking option will have priority over debug level set in
     * libc.debug.malloc system property. */
    if (__system_property_get("ro.kernel.qemu", env) && atoi(env)) {
        qemu_running = 1;
        if (__system_property_get("ro.kernel.memcheck", memcheck_tracing)) {
            if (memcheck_tracing[0] != '0') {
                // Emulator has started with memory tracing enabled. Enforce it.
                debug_level = 20;
                memcheck_enabled = 1;
            }
        }
    }

    /* If debug level has not been set by memcheck option in the emulator,
     * lets grab it from libc.debug.malloc system property. */
    if (!debug_level && __system_property_get("libc.debug.malloc", env)) {
        debug_level = atoi(env);
    }

    /* Debug level 0 means that we should use dlxxx allocation
     * routines (default). */
    if (!debug_level) {
        return;
    }

    // Lets see which .so must be loaded for the requested debug level
    switch (debug_level) {
        case 1:
        case 5:
        case 10:
            so_name = "/system/lib/libc_malloc_debug_leak.so";
            break;
        case 20:
            // Quick check: debug level 20 can only be handled in emulator.
            if (!qemu_running) {
                error_log("%s: Debug level %d can only be set in emulator\n",
                          __progname, debug_level);
                return;
            }
            // Make sure that memory checking has been enabled in emulator.
            if (!memcheck_enabled) {
                error_log("%s: Memory checking is not enabled in the emulator\n",
                          __progname);
                return;
            }
            so_name = "/system/lib/libc_malloc_debug_qemu.so";
            break;
        default:
            error_log("%s: Debug level %d is unknown\n",
                      __progname, debug_level);
            return;
    }

    // Load .so that implements the required malloc debugging functionality.
    libc_malloc_impl_handle = dlopen(so_name, RTLD_LAZY);
    if (libc_malloc_impl_handle == NULL) {
        error_log("%s: Missing module %s required for malloc debug level %d\n",
                 __progname, so_name, debug_level);
        return;
    }

    // Initialize malloc debugging in the loaded module.
    malloc_debug_initialize =
            dlsym(libc_malloc_impl_handle, "malloc_debug_initialize");
    if (malloc_debug_initialize == NULL) {
        error_log("%s: Initialization routine is not found in %s\n",
                  __progname, so_name);
        dlclose(libc_malloc_impl_handle);
        return;
    }
    if (malloc_debug_initialize()) {
        dlclose(libc_malloc_impl_handle);
        return;
    }

    if (debug_level == 20) {
        // For memory checker we need to do extra initialization.
        int (*memcheck_initialize)(int, const char*) =
                dlsym(libc_malloc_impl_handle, "memcheck_initialize");
        if (memcheck_initialize == NULL) {
            error_log("%s: memcheck_initialize routine is not found in %s\n",
                      __progname, so_name);
            dlclose(libc_malloc_impl_handle);
            return;
        }
        if (memcheck_initialize(MALLOC_ALIGNMENT, memcheck_tracing)) {
            dlclose(libc_malloc_impl_handle);
            return;
        }
    }

    // Initialize malloc dispatch table with appropriate routines.
    switch (debug_level) {
        case 1:
            __libc_android_log_print(ANDROID_LOG_INFO, "libc",
                    "%s using MALLOC_DEBUG = %d (leak checker)\n",
                    __progname, debug_level);
            gMallocUse.malloc =
                dlsym(libc_malloc_impl_handle, "leak_malloc");
            gMallocUse.free =
                dlsym(libc_malloc_impl_handle, "leak_free");
            gMallocUse.calloc =
                dlsym(libc_malloc_impl_handle, "leak_calloc");
            gMallocUse.realloc =
                dlsym(libc_malloc_impl_handle, "leak_realloc");
            gMallocUse.memalign =
                dlsym(libc_malloc_impl_handle, "leak_memalign");
            break;
        case 5:
            __libc_android_log_print(ANDROID_LOG_INFO, "libc",
                    "%s using MALLOC_DEBUG = %d (fill)\n",
                    __progname, debug_level);
            gMallocUse.malloc =
                dlsym(libc_malloc_impl_handle, "fill_malloc");
            gMallocUse.free =
                dlsym(libc_malloc_impl_handle, "fill_free");
            gMallocUse.calloc = dlcalloc;
            gMallocUse.realloc =
                dlsym(libc_malloc_impl_handle, "fill_realloc");
            gMallocUse.memalign =
                dlsym(libc_malloc_impl_handle, "fill_memalign");
            break;
        case 10:
            __libc_android_log_print(ANDROID_LOG_INFO, "libc",
                    "%s using MALLOC_DEBUG = %d (sentinels, fill)\n",
                    __progname, debug_level);
            gMallocUse.malloc =
                dlsym(libc_malloc_impl_handle, "chk_malloc");
            gMallocUse.free =
                dlsym(libc_malloc_impl_handle, "chk_free");
            gMallocUse.calloc =
                dlsym(libc_malloc_impl_handle, "chk_calloc");
            gMallocUse.realloc =
                dlsym(libc_malloc_impl_handle, "chk_realloc");
            gMallocUse.memalign =
                dlsym(libc_malloc_impl_handle, "chk_memalign");
            break;
        case 20:
            __libc_android_log_print(ANDROID_LOG_INFO, "libc",
                "%s[%u] using MALLOC_DEBUG = %d (instrumented for emulator)\n",
                __progname, getpid(), debug_level);
            gMallocUse.malloc =
                dlsym(libc_malloc_impl_handle, "qemu_instrumented_malloc");
            gMallocUse.free =
                dlsym(libc_malloc_impl_handle, "qemu_instrumented_free");
            gMallocUse.calloc =
                dlsym(libc_malloc_impl_handle, "qemu_instrumented_calloc");
            gMallocUse.realloc =
                dlsym(libc_malloc_impl_handle, "qemu_instrumented_realloc");
            gMallocUse.memalign =
                dlsym(libc_malloc_impl_handle, "qemu_instrumented_memalign");
            break;
        default:
            break;
    }

    // Make sure dispatch table is initialized
    if ((gMallocUse.malloc == NULL) ||
        (gMallocUse.free == NULL) ||
        (gMallocUse.calloc == NULL) ||
        (gMallocUse.realloc == NULL) ||
        (gMallocUse.memalign == NULL)) {
        error_log("%s: Cannot initialize malloc dispatch table for debug level"
                  " %d: %p, %p, %p, %p, %p\n",
                  __progname, debug_level,
                  gMallocUse.malloc, gMallocUse.free,
                  gMallocUse.calloc, gMallocUse.realloc,
                  gMallocUse.memalign);
        dlclose(libc_malloc_impl_handle);
        libc_malloc_impl_handle = NULL;
    } else {
        __libc_malloc_dispatch = &gMallocUse;
    }
}

static pthread_once_t  malloc_init_once_ctl = PTHREAD_ONCE_INIT;

#endif  // !LIBC_STATIC
#endif  // USE_DL_PREFIX

/* Initializes memory allocation framework.
 * This routine is called from __libc_init routines implemented
 * in libc_init_static.c and libc_init_dynamic.c files.
 */
void malloc_debug_init(void)
{
    /* We need to initialize malloc iff we implement here custom
     * malloc routines (i.e. USE_DL_PREFIX is defined) for libc.so */
#if defined(USE_DL_PREFIX) && !defined(LIBC_STATIC)
    if (pthread_once(&malloc_init_once_ctl, malloc_init_impl)) {
        error_log("Unable to initialize malloc_debug component.");
    }
#endif  // USE_DL_PREFIX && !LIBC_STATIC
}
