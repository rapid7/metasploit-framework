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
 * Contains implementation of memory allocation routines instrumented for
 * usage in the emulator to detect memory allocation violations, such as
 * memory leaks, buffer overruns, etc.
 * Code, implemented here is intended to run in the emulated environment only,
 * and serves simply as hooks into memory allocation routines. Main job of this
 * code is to notify the emulator about memory being allocated/deallocated,
 * providing information about each allocation. The idea is that emulator will
 * keep list of currently allocated blocks, and, knowing boundaries of each
 * block it will be able to verify that ld/st access to these blocks don't step
 * over boundaries set for the user. To enforce that, each memory block
 * allocated by this code is guarded with "prefix" and "suffix" areas, so
 * every time emulator detects access to any of these guarding areas, it can be
 * considered as access violation.
 */

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include "dlmalloc.h"
#include "logd.h"
#include "malloc_debug_common.h"

/* This file should be included into the build only when
 * MALLOC_QEMU_INSTRUMENT macro is defined. */
#ifndef MALLOC_QEMU_INSTRUMENT
#error MALLOC_QEMU_INSTRUMENT is not defined.
#endif  // !MALLOC_QEMU_INSTRUMENT

/* Controls access violation test performed to make sure that we catch AVs
 * all the time they occur. See test_access_violation for more info. This macro
 * is used for internal testing purposes and should always be set to zero for
 * the production builds. */
#define TEST_ACCESS_VIOLATIONS  0

// =============================================================================
// Communication structures
// =============================================================================

/* Describes memory block allocated from the heap. This structure is passed
 * along with TRACE_DEV_REG_MALLOC event. This descriptor is used to inform
 * the emulator about new memory block being allocated from the heap. The entire
 * structure is initialized by the guest system before event is fired up. It is
 * important to remember that same structure (an exact copy, except for
 * replacing pointers with target_ulong) is also declared in the emulator's
 * sources (file memcheck/memcheck_common.h). So, every time a change is made to
 * any of these two declaration, another one must be also updated accordingly.
 */
typedef struct MallocDesc {
    /* Pointer to the memory block actually allocated from the heap. Note that
     * this is not the pointer that is returned to the malloc's caller. Pointer
     * returned to the caller is calculated by adding value stored in this field
     * to the value stored in prefix_size field of this structure.
     */
    void*       ptr;

    /* Number of bytes requested by the malloc's caller. */
    uint32_t    requested_bytes;

    /* Byte size of the prefix data. Actual pointer returned to the malloc's
     * caller is calculated by adding value stored in this field to the value
     * stored in in the ptr field of this structure.
     */
    uint32_t    prefix_size;

    /* Byte size of the suffix data. */
    uint32_t    suffix_size;

    /* Id of the process that initialized libc instance, in which allocation
     * has occurred. This field is used by the emulator to report errors in
     * the course of TRACE_DEV_REG_MALLOC event handling. In case of an error,
     * emulator sets this field to zero (invalid value for a process ID).
     */
    uint32_t    libc_pid;

    /* Id of the process in context of which allocation has occurred.
     * Value in this field may differ from libc_pid value, if process that
     * is doing allocation has been forked from the process that initialized
     * libc instance.
     */
    uint32_t    allocator_pid;

    /* Number of access violations detected on this allocation. */
    uint32_t    av_count;
} MallocDesc;

/* Describes memory block info queried from emulator. This structure is passed
 * along with TRACE_DEV_REG_QUERY_MALLOC event. When handling free and realloc
 * calls, it is required that we have information about memory blocks that were
 * actually allocated in previous calls to malloc, calloc, memalign, or realloc.
 * Since we don't keep this information directly in the allocated block, but
 * rather we keep it in the emulator, we need to query emulator for that
 * information with TRACE_DEV_REG_QUERY_MALLOC query. The entire structure is
 * initialized by the guest system before event is fired up. It is important to
 * remember that same structure (an exact copy, except for replacing pointers
 * with target_ulong) is also declared in the emulator's sources (file
 * memcheck/memecheck_common.h). So, every time a change is made to any of these
 * two declaration, another one must be also updated accordingly.
 */
typedef struct MallocDescQuery {
    /* Pointer, for which information is queried. Note that this pointer doesn't
     * have to be exact pointer returned to malloc's caller, but can point
     * anywhere inside an allocated block, including guarding areas. Emulator
     * will respond with information about allocated block that contains this
     * pointer.
     */
    void*       ptr;

    /* Id of the process that initialized libc instance, in which this query
     * is called. This field is used by the emulator to report errors in
     * the course of TRACE_DEV_REG_QUERY_MALLOC event handling. In case of an
     * error, emulator sets this field to zero (invalid value for a process ID).
     */
    uint32_t    libc_pid;

    /* Process ID in context of which query is made. */
    uint32_t    query_pid;

    /* Code of the allocation routine, in context of which query has been made:
     *  1 - free
     *  2 - realloc
     */
    uint32_t    routine;

    /* Address of memory allocation descriptor for the queried pointer.
     * Descriptor, addressed by this field is initialized by the emulator in
     * response to the query.
     */
    MallocDesc*  desc;
} MallocDescQuery;

/* Describes memory block that is being freed back to the heap. This structure
 * is passed along with TRACE_DEV_REG_FREE_PTR event. The entire structure is
 * initialized by the guest system before event is fired up. It is important to
 * remember that same structure (an exact copy, except for replacing pointers
 * with target_ulong) is also declared in the emulator's sources (file
 * memcheck/memecheck_common.h). So, every time a change is made to any of these
 * two declaration, another one must be also updated accordingly.
 */
typedef struct MallocFree {
    /* Pointer to be freed. */
    void*       ptr;

    /* Id of the process that initialized libc instance, in which this free
     * is called. This field is used by the emulator to report errors in
     * the course of TRACE_DEV_REG_FREE_PTR event handling. In case of an
     * error, emulator sets this field to zero (invalid value for a process ID).
     */
    uint32_t    libc_pid;

    /* Process ID in context of which memory is being freed. */
    uint32_t    free_pid;
} MallocFree;

// =============================================================================
// Communication events
// =============================================================================

/* Notifies the emulator that libc has been initialized for a process.
 * Event's value parameter is PID for the process in context of which libc has
 * been initialized.
 */
#define TRACE_DEV_REG_LIBC_INIT             1536

/* Notifies the emulator about new memory block been allocated.
 * Event's value parameter points to MallocDesc instance that contains
 * allocated block information. Note that 'libc_pid' field of the descriptor
 * is used by emulator to report failure in handling this event. In case
 * of a failure emulator will zero that field before completing this event.
 */
#define TRACE_DEV_REG_MALLOC                1537

/* Notifies the emulator about memory block being freed.
 * Event's value parameter points to MallocFree descriptor that contains
 * information about block that's being freed. Note that 'libc_pid' field
 * of the descriptor is used by emulator to report failure in handling this
 * event. In case of a failure emulator will zero that field before completing
 * this event.
 */
#define TRACE_DEV_REG_FREE_PTR              1538

/* Queries the emulator about allocated memory block information.
 * Event's value parameter points to MallocDescQuery descriptor that contains
 * query parameters. Note that 'libc_pid' field of the descriptor is used by
 * emulator to report failure in handling this event. In case of a failure
 * emulator will zero that field before completing this event.
 */
#define TRACE_DEV_REG_QUERY_MALLOC          1539

/* Queries the emulator to print a string to its stdout.
 * Event's value parameter points to a zero-terminated string to be printed.
 */
#define TRACE_DEV_REG_PRINT_USER_STR        1540

static void notify_qemu_string(const char* str);
static void qemu_log(int prio, const char* fmt, ...);
static void dump_malloc_descriptor(char* str,
                                   size_t str_buf_size,
                                   const MallocDesc* desc);

// =============================================================================
// Macros
// =============================================================================

/* Defines default size of allocation prefix.
 * Note that we make prefix area quite large in order to increase chances of
 * catching buffer overflow. */
#define DEFAULT_PREFIX_SIZE     (malloc_alignment * 4)

/* Defines default size of allocation suffix.
 * Note that we make suffix area quite large in order to increase chances of
 * catching buffer overflow. */
#define DEFAULT_SUFFIX_SIZE     (malloc_alignment * 4)

/* Debug tracing has been enabled by the emulator. */
#define DEBUG_TRACING_ENABLED   0x00000001
/* Error tracing has been enabled by the emulator. */
#define ERROR_TRACING_ENABLED   0x00000002
/* Info tracing has been enabled by the emulator. */
#define INFO_TRACING_ENABLED    0x00000004
/* All tracing flags combined. */
#define ALL_TRACING_ENABLED (DEBUG_TRACING_ENABLED |    \
                             ERROR_TRACING_ENABLED |    \
                             INFO_TRACING_ENABLED)

/* Prints a string to the emulator's stdout.
 * In early stages of system loading, logging mesages via
 * __libc_android_log_print API is not available, because ADB API has not been
 * hooked up yet. So, in order to see such messages we need to print them to
 * the emulator's stdout.
 * Parameters passed to this macro are the same as parameters for printf
 * routine.
 */
#define TR(...)                                         \
    do {                                                \
        char tr_str[4096];                              \
        snprintf(tr_str, sizeof(tr_str), __VA_ARGS__ ); \
        tr_str[sizeof(tr_str) - 1] = '\0';              \
        notify_qemu_string(&tr_str[0]);                 \
    } while (0)

// =============================================================================
// Logging macros. Note that we simultaneously log messages to ADB and emulator.
// =============================================================================

/*
 * Helper macros for checking if particular trace level is enabled.
 */
#define debug_LOG_ENABLED       ((tracing_flags & DEBUG_TRACING_ENABLED) != 0)
#define error_LOG_ENABLED       ((tracing_flags & ERROR_TRACING_ENABLED) != 0)
#define info_LOG_ENABLED        ((tracing_flags & INFO_TRACING_ENABLED)  != 0)
#define tracing_enabled(type)   (type##_LOG_ENABLED)

/*
 * Logging helper macros.
 */
#define debug_log(format, ...)                                              \
    do {                                                                    \
        __libc_android_log_print(ANDROID_LOG_DEBUG, "memcheck",             \
                                 (format), ##__VA_ARGS__ );                 \
        if (tracing_flags & DEBUG_TRACING_ENABLED) {                        \
            qemu_log(ANDROID_LOG_DEBUG, (format), ##__VA_ARGS__ );          \
        }                                                                   \
    } while (0)

#define error_log(format, ...)                                              \
    do {                                                                    \
        __libc_android_log_print(ANDROID_LOG_ERROR, "memcheck",             \
                                 (format), ##__VA_ARGS__ );                 \
        if (tracing_flags & ERROR_TRACING_ENABLED) {                        \
            qemu_log(ANDROID_LOG_ERROR, (format), ##__VA_ARGS__ );          \
        }                                                                   \
    } while (0)

#define info_log(format, ...)                                               \
    do {                                                                    \
        __libc_android_log_print(ANDROID_LOG_INFO, "memcheck",              \
                                 (format), ##__VA_ARGS__ );                 \
        if (tracing_flags & INFO_TRACING_ENABLED) {                         \
            qemu_log(ANDROID_LOG_INFO, (format), ##__VA_ARGS__ );           \
        }                                                                   \
    } while (0)

/* Logs message dumping MallocDesc instance at the end of the message.
 * Param:
 *  type - Message type: debug, error, or info
 *  desc - MallocDesc instance to dump.
 *  frmt + rest - Formats message preceding dumped descriptor.
*/
#define log_mdesc(type, desc, frmt, ...)                                    \
    do {                                                                    \
        if (tracing_enabled(type)) {                                        \
            char log_str[4096];                                             \
            size_t str_len;                                                 \
            snprintf(log_str, sizeof(log_str), frmt, ##__VA_ARGS__);        \
            log_str[sizeof(log_str) - 1] = '\0';                            \
            str_len = strlen(log_str);                                      \
            dump_malloc_descriptor(log_str + str_len,                       \
                                   sizeof(log_str) - str_len,               \
                                   (desc));                                 \
            type##_log(log_str);                                            \
        }                                                                   \
    } while (0)

// =============================================================================
// Static data
// =============================================================================

/* Emulator's magic page address.
 * This page (mapped on /dev/qemu_trace device) is used to fire up events
 * in the emulator. */
static volatile void* qtrace = NULL;

/* Cached PID of the process in context of which this libc instance
 * has been initialized. */
static uint32_t malloc_pid = 0;

/* Memory allocation alignment that is used in dlmalloc.
 * This variable is updated by memcheck_initialize routine. */
static uint32_t malloc_alignment = 8;

/* Tracing flags. These flags control which types of logging messages are
 * enabled by the emulator. See XXX_TRACING_ENABLED for the values of flags
 * stored in this variable. This variable is updated by memcheck_initialize
 * routine. */
static uint32_t tracing_flags = 0;

// =============================================================================
// Static routines
// =============================================================================

/* Gets pointer, returned to malloc caller for the given allocation decriptor.
 * Param:
 *  desc - Allocation descriptor.
 * Return:
 *  Pointer to the allocated memory returned to the malloc caller.
 */
static inline void*
mallocdesc_user_ptr(const MallocDesc* desc)
{
    return (char*)desc->ptr + desc->prefix_size;
}

/* Gets size of memory block actually allocated from the heap for the given
 * allocation decriptor.
 * Param:
 *  desc - Allocation descriptor.
 * Return:
 *  Size of memory block actually allocated from the heap.
 */
static inline uint32_t
mallocdesc_alloc_size(const MallocDesc* desc)
{
    return desc->prefix_size + desc->requested_bytes + desc->suffix_size;
}

/* Gets pointer to the end of the allocated block for the given descriptor.
 * Param:
 *  desc - Descriptor for the memory block, allocated in malloc handler.
 * Return:
 *  Pointer to the end of (one byte past) the allocated block.
 */
static inline void*
mallocdesc_alloc_end(const MallocDesc* desc)
{
    return (char*)desc->ptr + mallocdesc_alloc_size(desc);
}

/* Fires up an event in the emulator.
 * Param:
 *  code - Event code (one of the TRACE_DEV_XXX).
 *  val  - Event's value parameter.
 */
static inline void
notify_qemu(uint32_t code, uint32_t val)
{
    if (NULL != qtrace) {
        *(volatile uint32_t*)((uint32_t)qtrace + ((code - 1024) << 2)) = val;
    }
}

/* Prints a zero-terminated string to the emulator's stdout (fires up
 * TRACE_DEV_REG_PRINT_USER_STR event in the emulator).
 * Param:
 *  str - Zero-terminated string to print.
 */
static void
notify_qemu_string(const char* str)
{
    if (str != NULL) {
        notify_qemu(TRACE_DEV_REG_PRINT_USER_STR, (uint32_t)str);
    }
}

/* Fires up TRACE_DEV_REG_LIBC_INIT event in the emulator.
 * Param:
 *  pid - ID of the process that initialized libc.
 */
static void
notify_qemu_libc_initialized(uint32_t pid)
{
    notify_qemu(TRACE_DEV_REG_LIBC_INIT, pid);
}

/* Fires up TRACE_DEV_REG_MALLOC event in the emulator.
 * Param:
 *  desc - Pointer to MallocDesc instance containing allocated block
 *      information.
 * Return:
 *  Zero on success, or -1 on failure. Note that on failure libc_pid field of
 *  the desc parameter passed to this routine has been zeroed out by the
 *  emulator.
 */
static inline int
notify_qemu_malloc(volatile MallocDesc* desc)
{
    desc->libc_pid = malloc_pid;
    desc->allocator_pid = getpid();
    desc->av_count = 0;
    notify_qemu(TRACE_DEV_REG_MALLOC, (uint32_t)desc);

    /* Emulator reports failure by zeroing libc_pid field of the
     * descriptor. */
    return desc->libc_pid != 0 ? 0 : -1;
}

/* Fires up TRACE_DEV_REG_FREE_PTR event in the emulator.
 * Param:
 *  ptr - Pointer to the memory block that's being freed.
 * Return:
 *  Zero on success, or -1 on failure.
 */
static inline int
notify_qemu_free(void* ptr_to_free)
{
    volatile MallocFree free_desc;

    free_desc.ptr = ptr_to_free;
    free_desc.libc_pid = malloc_pid;
    free_desc.free_pid = getpid();
    notify_qemu(TRACE_DEV_REG_FREE_PTR, (uint32_t)&free_desc);

    /* Emulator reports failure by zeroing libc_pid field of the
     * descriptor. */
    return free_desc.libc_pid != 0 ? 0 : -1;
}

/* Fires up TRACE_DEV_REG_QUERY_MALLOC event in the emulator.
 * Param:
 *  ptr - Pointer to request allocation information for.
 *  desc - Pointer to MallocDesc instance that will receive allocation
 *      information.
 *  routine - Code of the allocation routine, in context of which query is made:
 *      1 - free
 *      2 - realloc
 * Return:
 *  Zero on success, or -1 on failure.
 */
static inline int
query_qemu_malloc_info(void* ptr, MallocDesc* desc, uint32_t routine)
{
    volatile MallocDescQuery query;

    query.ptr = ptr;
    query.libc_pid = malloc_pid;
    query.query_pid = getpid();
    query.routine = routine;
    query.desc = desc;
    notify_qemu(TRACE_DEV_REG_QUERY_MALLOC, (uint32_t)&query);

    /* Emulator reports failure by zeroing libc_pid field of the
     * descriptor. */
    return query.libc_pid != 0 ? 0 : -1;
}

/* Logs a message to emulator's stdout.
 * Param:
 *  prio - Message priority (debug, info, or error)
 *  fmt + rest - Message format and parameters.
 */
static void
qemu_log(int prio, const char* fmt, ...)
{
    va_list ap;
    char buf[4096];
    const char* prefix;

    /* Choose message prefix depending on the priority value. */
    switch (prio) {
        case ANDROID_LOG_ERROR:
            if (!tracing_enabled(error)) {
                return;
            }
            prefix = "E";
            break;
        case ANDROID_LOG_INFO:
            if (!tracing_enabled(info)) {
                return;
            }
            prefix = "I";
            break;
        case ANDROID_LOG_DEBUG:
        default:
            if (!tracing_enabled(debug)) {
                return;
            }
            prefix = "D";
            break;
    }

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = '\0';

    TR("%s/memcheck: %s\n", prefix, buf);
}

/* Dumps content of memory allocation descriptor to a string.
 * Param:
 *  str - String to dump descriptor to.
 *  str_buf_size - Size of string's buffer.
 *  desc - Descriptor to dump.
 */
static void
dump_malloc_descriptor(char* str, size_t str_buf_size, const MallocDesc* desc)
{
    if (str_buf_size) {
        snprintf(str, str_buf_size,
            "MDesc: %p: %X <-> %X [%u + %u + %u] by pid=%03u in libc_pid=%03u",
            mallocdesc_user_ptr(desc), (uint32_t)desc->ptr,
            (uint32_t)mallocdesc_alloc_end(desc), desc->prefix_size,
            desc->requested_bytes, desc->suffix_size, desc->allocator_pid,
            desc->libc_pid);
        str[str_buf_size - 1] = '\0';
    }
}

#if TEST_ACCESS_VIOLATIONS
/* Causes an access violation on allocation descriptor, and verifies that
 * violation has been detected by memory checker in the emulator.
 */
static void
test_access_violation(const MallocDesc* desc)
{
    MallocDesc desc_chk;
    char ch;
    volatile char* prefix = (volatile char*)desc->ptr;
    volatile char* suffix = (volatile char*)mallocdesc_user_ptr(desc) +
                                            desc->requested_bytes;
    /* We're causing AV by reading from the prefix and suffix areas of the
     * allocated block. This should produce two access violations, so when we
     * get allocation descriptor from QEMU, av_counter should be bigger than
     * av_counter of the original descriptor by 2. */
    ch = *prefix;
    ch = *suffix;
    if (!query_qemu_malloc_info(mallocdesc_user_ptr(desc), &desc_chk, 2) &&
        desc_chk.av_count != (desc->av_count + 2)) {
        log_mdesc(error, &desc_chk,
                  "<libc_pid=%03u, pid=%03u>: malloc: Access violation test failed:\n"
                  "Expected violations count %u is not equal to the actually reported %u",
                  malloc_pid, getpid(), desc->av_count + 2,
                  desc_chk.av_count);
    }
}
#endif  // TEST_ACCESS_VIOLATIONS

// =============================================================================
// API routines
// =============================================================================

void* qemu_instrumented_malloc(size_t bytes);
void  qemu_instrumented_free(void* mem);
void* qemu_instrumented_calloc(size_t n_elements, size_t elem_size);
void* qemu_instrumented_realloc(void* mem, size_t bytes);
void* qemu_instrumented_memalign(size_t alignment, size_t bytes);

/* Initializes malloc debugging instrumentation for the emulator.
 * This routine is called from malloc_init_impl routine implemented in
 * bionic/libc/bionic/malloc_debug_common.c when malloc debugging gets
 * initialized for a process. The way malloc debugging implementation is
 * done, it is guaranteed that this routine will be called just once per
 * process.
 * Return:
 *  0 on success, or -1 on failure.
*/
int
malloc_debug_initialize(void)
{
    /* We will be using emulator's magic page to report memory allocation
     * activities. In essence, what magic page does, it translates writes to
     * the memory mapped spaces into writes to an I/O port that emulator
     * "listens to" on the other end. Note that until we open and map that
     * device, logging to emulator's stdout will not be available. */
    int fd = open("/dev/qemu_trace", O_RDWR);
    if (fd < 0) {
        error_log("Unable to open /dev/qemu_trace");
        return -1;
    } else {
        qtrace = mmap(0, PAGESIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        close(fd);

        if (qtrace == MAP_FAILED) {
            qtrace = NULL;
            error_log("Unable to mmap /dev/qemu_trace");
            return -1;
        }
    }

    /* Cache pid of the process this library has been initialized for. */
    malloc_pid = getpid();

    return 0;
}

/* Completes malloc debugging instrumentation for the emulator.
 * Note that this routine is called after successful return from
 * malloc_debug_initialize, which means that connection to the emulator via
 * "magic page" has been established.
 * Param:
 *  alignment - Alignment requirement set for memiry allocations.
 *  memcheck_param - Emulator's -memcheck option parameters. This string
 *      contains abbreviation for guest events that are enabled for tracing.
 * Return:
 *  0 on success, or -1 on failure.
*/
int
memcheck_initialize(int alignment, const char* memcheck_param)
{
    malloc_alignment = alignment;

    /* Parse -memcheck parameter for the guest tracing flags. */
    while (*memcheck_param != '\0') {
        switch (*memcheck_param) {
            case 'a':
                // Enable all messages from the guest.
                tracing_flags |= ALL_TRACING_ENABLED;
                break;
            case 'd':
                // Enable debug messages from the guest.
                tracing_flags |= DEBUG_TRACING_ENABLED;
                break;
            case 'e':
                // Enable error messages from the guest.
                tracing_flags |= ERROR_TRACING_ENABLED;
                break;
            case 'i':
                // Enable info messages from the guest.
                tracing_flags |= INFO_TRACING_ENABLED;
                break;
            default:
                break;
        }
        if (tracing_flags == ALL_TRACING_ENABLED) {
            break;
        }
        memcheck_param++;
    }

    notify_qemu_libc_initialized(malloc_pid);

    debug_log("Instrumented for pid=%03u: malloc=%p, free=%p, calloc=%p, realloc=%p, memalign=%p",
              malloc_pid, qemu_instrumented_malloc, qemu_instrumented_free,
              qemu_instrumented_calloc, qemu_instrumented_realloc,
              qemu_instrumented_memalign);

    return 0;
}

/* This routine serves as entry point for 'malloc'.
 * Primary responsibility of this routine is to allocate requested number of
 * bytes (plus prefix, and suffix guards), and report allocation to the
 * emulator.
 */
void*
qemu_instrumented_malloc(size_t bytes)
{
    MallocDesc desc;

    /* Initialize block descriptor and allocate memory. Note that dlmalloc
     * returns a valid pointer on zero allocation. Lets mimic this behavior. */
    desc.prefix_size = DEFAULT_PREFIX_SIZE;
    desc.requested_bytes = bytes;
    desc.suffix_size = DEFAULT_SUFFIX_SIZE;
    desc.ptr = dlmalloc(mallocdesc_alloc_size(&desc));
    if (desc.ptr == NULL) {
        error_log("<libc_pid=%03u, pid=%03u> malloc(%u): dlmalloc(%u) failed.",
                  malloc_pid, getpid(), bytes, mallocdesc_alloc_size(&desc));
        return NULL;
    }

    // Fire up event in the emulator.
    if (notify_qemu_malloc(&desc)) {
        log_mdesc(error, &desc, "<libc_pid=%03u, pid=%03u>: malloc: notify_malloc failed for ",
                  malloc_pid, getpid());
        dlfree(desc.ptr);
        return NULL;
    } else {
#if TEST_ACCESS_VIOLATIONS
        test_access_violation(&desc);
#endif  // TEST_ACCESS_VIOLATIONS
        log_mdesc(info, &desc, "+++ <libc_pid=%03u, pid=%03u> malloc(%u) -> ",
                  malloc_pid, getpid(), bytes);
        return mallocdesc_user_ptr(&desc);
    }
}

/* This routine serves as entry point for 'malloc'.
 * Primary responsibility of this routine is to free requested memory, and
 * report free block to the emulator.
 */
void
qemu_instrumented_free(void* mem)
{
    MallocDesc desc;

    if (mem == NULL) {
        // Just let go NULL free
        dlfree(mem);
        return;
    }

    // Query emulator for the freeing block information.
    if (query_qemu_malloc_info(mem, &desc, 1)) {
        error_log("<libc_pid=%03u, pid=%03u>: free(%p) query_info failed.",
                  malloc_pid, getpid(), mem);
        return;
    }

#if TEST_ACCESS_VIOLATIONS
    test_access_violation(&desc);
#endif  // TEST_ACCESS_VIOLATIONS

    /* Make sure that pointer that's being freed matches what we expect
     * for this memory block. Note that this violation should be already
     * caught in the emulator. */
    if (mem != mallocdesc_user_ptr(&desc)) {
        log_mdesc(error, &desc, "<libc_pid=%03u, pid=%03u>: free(%p) is invalid for ",
                  malloc_pid, getpid(), mem);
        return;
    }

    // Fire up event in the emulator and free block that was actually allocated.
    if (notify_qemu_free(mem)) {
        log_mdesc(error, &desc, "<libc_pid=%03u, pid=%03u>: free(%p) notify_free failed for ",
                  malloc_pid, getpid(), mem);
    } else {
        log_mdesc(info, &desc, "--- <libc_pid=%03u, pid=%03u> free(%p) -> ",
                  malloc_pid, getpid(), mem);
        dlfree(desc.ptr);
    }
}

/* This routine serves as entry point for 'calloc'.
 * This routine behaves similarly to qemu_instrumented_malloc.
 */
void*
qemu_instrumented_calloc(size_t n_elements, size_t elem_size)
{
    MallocDesc desc;
    void* ret;
    size_t total_size;
    size_t total_elements;

    if (n_elements == 0 || elem_size == 0) {
        // Just let go zero bytes allocation.
        info_log("::: <libc_pid=%03u, pid=%03u>: Zero calloc redir to malloc",
                 malloc_pid, getpid());
        return qemu_instrumented_malloc(0);
    }

    /* Fail on overflow - just to be safe even though this code runs only
     * within the debugging C library, not the production one */
    if (n_elements && MAX_SIZE_T / n_elements < elem_size) {
        return NULL;
    }

    /* Calculating prefix size. The trick here is to make sure that
     * first element (returned to the caller) is properly aligned. */
    if (DEFAULT_PREFIX_SIZE >= elem_size) {
        /* If default alignment is bigger than element size, we will
         * set our prefix size to the default alignment size. */
        desc.prefix_size = DEFAULT_PREFIX_SIZE;
        /* For the suffix we will use whatever bytes remain from the prefix
         * allocation size, aligned to the size of an element, plus the usual
         * default suffix size. */
        desc.suffix_size = (DEFAULT_PREFIX_SIZE % elem_size) +
                           DEFAULT_SUFFIX_SIZE;
    } else {
        /* Make sure that prefix, and suffix sizes is at least elem_size,
         * and first element returned to the caller is properly aligned. */
        desc.prefix_size = elem_size + DEFAULT_PREFIX_SIZE - 1;
        desc.prefix_size &= ~(malloc_alignment - 1);
        desc.suffix_size = DEFAULT_SUFFIX_SIZE;
    }
    desc.requested_bytes = n_elements * elem_size;
    total_size = desc.requested_bytes + desc.prefix_size + desc.suffix_size;
    total_elements = total_size / elem_size;
    total_size %= elem_size;
    if (total_size != 0) {
        // Add extra to the suffix area.
        total_elements++;
        desc.suffix_size += (elem_size - total_size);
    }
    desc.ptr = dlcalloc(total_elements, elem_size);
    if (desc.ptr == NULL) {
        error_log("<libc_pid=%03u, pid=%03u> calloc: dlcalloc(%u(%u), %u) (prx=%u, sfx=%u) failed.",
                   malloc_pid, getpid(), n_elements, total_elements, elem_size,
                   desc.prefix_size, desc.suffix_size);
        return NULL;
    }

    if (notify_qemu_malloc(&desc)) {
        log_mdesc(error, &desc, "<libc_pid=%03u, pid=%03u>: calloc(%u(%u), %u): notify_malloc failed for ",
                  malloc_pid, getpid(), n_elements, total_elements, elem_size);
        dlfree(desc.ptr);
        return NULL;
    } else {
#if TEST_ACCESS_VIOLATIONS
        test_access_violation(&desc);
#endif  // TEST_ACCESS_VIOLATIONS
        log_mdesc(info, &desc, "### <libc_pid=%03u, pid=%03u> calloc(%u(%u), %u) -> ",
                  malloc_pid, getpid(), n_elements, total_elements, elem_size);
        return mallocdesc_user_ptr(&desc);
    }
}

/* This routine serves as entry point for 'realloc'.
 * This routine behaves similarly to qemu_instrumented_free +
 * qemu_instrumented_malloc. Note that this modifies behavior of "shrinking" an
 * allocation, but overall it doesn't seem to matter, as caller of realloc
 * should not expect that pointer returned after shrinking will remain the same.
 */
void*
qemu_instrumented_realloc(void* mem, size_t bytes)
{
    MallocDesc new_desc;
    MallocDesc cur_desc;
    size_t to_copy;
    void* ret;

    if (mem == NULL) {
        // Nothing to realloc. just do regular malloc.
        info_log("::: <libc_pid=%03u, pid=%03u>: realloc(%p, %u) redir to malloc",
                 malloc_pid, getpid(), mem, bytes);
        return qemu_instrumented_malloc(bytes);
    }

    if (bytes == 0) {
        // This is a "free" condition.
        info_log("::: <libc_pid=%03u, pid=%03u>: realloc(%p, %u) redir to free and malloc",
                 malloc_pid, getpid(), mem, bytes);
        qemu_instrumented_free(mem);

        // This is what dlrealloc does for a "free" realloc.
        return NULL;
    }

    // Query emulator for the reallocating block information.
    if (query_qemu_malloc_info(mem, &cur_desc, 2)) {
        // Note that this violation should be already caught in the emulator.
        error_log("<libc_pid=%03u, pid=%03u>: realloc(%p, %u) query_info failed.",
                  malloc_pid, getpid(), mem, bytes);
        return NULL;
    }

#if TEST_ACCESS_VIOLATIONS
    test_access_violation(&cur_desc);
#endif  // TEST_ACCESS_VIOLATIONS

    /* Make sure that reallocating pointer value is what we would expect
     * for this memory block. Note that this violation should be already caught
     * in the emulator.*/
    if (mem != mallocdesc_user_ptr(&cur_desc)) {
        log_mdesc(error, &cur_desc, "<libc_pid=%03u, pid=%03u>: realloc(%p, %u) is invalid for ",
                  malloc_pid, getpid(), mem, bytes);
        return NULL;
    }

    /* TODO: We're a bit inefficient here, always allocating new block from
     * the heap. If this realloc shrinks current buffer, we can just do the
     * shrinking "in place", adjusting suffix_size in the allocation descriptor
     * for this block that is stored in the emulator. */

    // Initialize descriptor for the new block.
    new_desc.prefix_size = DEFAULT_PREFIX_SIZE;
    new_desc.requested_bytes = bytes;
    new_desc.suffix_size = DEFAULT_SUFFIX_SIZE;
    new_desc.ptr = dlmalloc(mallocdesc_alloc_size(&new_desc));
    if (new_desc.ptr == NULL) {
        log_mdesc(error, &cur_desc, "<libc_pid=%03u, pid=%03u>: realloc(%p, %u): dlmalloc(%u) failed on ",
                  malloc_pid, getpid(), mem, bytes,
                  mallocdesc_alloc_size(&new_desc));
        return NULL;
    }
    ret = mallocdesc_user_ptr(&new_desc);

    // Copy user data from old block to the new one.
    to_copy = bytes < cur_desc.requested_bytes ? bytes :
                                                 cur_desc.requested_bytes;
    if (to_copy != 0) {
        memcpy(ret, mallocdesc_user_ptr(&cur_desc), to_copy);
    }

    // Register new block with emulator.
    if(notify_qemu_malloc(&new_desc)) {
        log_mdesc(error, &new_desc, "<libc_pid=%03u, pid=%03u>: realloc(%p, %u) notify_malloc failed -> ",
                  malloc_pid, getpid(), mem, bytes);
        log_mdesc(error, &cur_desc, "                                                                <- ");
        dlfree(new_desc.ptr);
        return NULL;
    }

#if TEST_ACCESS_VIOLATIONS
    test_access_violation(&new_desc);
#endif  // TEST_ACCESS_VIOLATIONS

    // Free old block.
    if (notify_qemu_free(mem)) {
        log_mdesc(error, &cur_desc, "<libc_pid=%03u, pid=%03u>: realloc(%p, %u): notify_free failed for ",
                  malloc_pid, getpid(), mem, bytes);
        /* Since we registered new decriptor with the emulator, we need
         * to unregister it before freeing newly allocated block. */
        notify_qemu_free(mallocdesc_user_ptr(&new_desc));
        dlfree(new_desc.ptr);
        return NULL;
    }
    dlfree(cur_desc.ptr);

    log_mdesc(info, &new_desc, "=== <libc_pid=%03u, pid=%03u>: realloc(%p, %u) -> ",
              malloc_pid, getpid(), mem, bytes);
    log_mdesc(info, &cur_desc, "                                               <- ");

    return ret;
}

/* This routine serves as entry point for 'memalign'.
 * This routine behaves similarly to qemu_instrumented_malloc.
 */
void*
qemu_instrumented_memalign(size_t alignment, size_t bytes)
{
    MallocDesc desc;

    if (bytes == 0) {
        // Just let go zero bytes allocation.
        info_log("::: <libc_pid=%03u, pid=%03u>: memalign(%X, %u) redir to malloc",
                 malloc_pid, getpid(), alignment, bytes);
        return qemu_instrumented_malloc(0);
    }

    /* Prefix size for aligned allocation must be equal to the alignment used
     * for allocation in order to ensure proper alignment of the returned
     * pointer, in case that alignment requirement is greater than prefix
     * size. */
    desc.prefix_size = alignment > DEFAULT_PREFIX_SIZE ? alignment :
                                                         DEFAULT_PREFIX_SIZE;
    desc.requested_bytes = bytes;
    desc.suffix_size = DEFAULT_SUFFIX_SIZE;
    desc.ptr = dlmemalign(desc.prefix_size, mallocdesc_alloc_size(&desc));
    if (desc.ptr == NULL) {
        error_log("<libc_pid=%03u, pid=%03u> memalign(%X, %u): dlmalloc(%u) failed.",
                  malloc_pid, getpid(), alignment, bytes,
                  mallocdesc_alloc_size(&desc));
        return NULL;
    }
    if (notify_qemu_malloc(&desc)) {
        log_mdesc(error, &desc, "<libc_pid=%03u, pid=%03u>: memalign(%X, %u): notify_malloc failed for ",
                  malloc_pid, getpid(), alignment, bytes);
        dlfree(desc.ptr);
        return NULL;
    }

#if TEST_ACCESS_VIOLATIONS
    test_access_violation(&desc);
#endif  // TEST_ACCESS_VIOLATIONS

    log_mdesc(info, &desc, "@@@ <libc_pid=%03u, pid=%03u> memalign(%X, %u) -> ",
              malloc_pid, getpid(), alignment, bytes);
    return mallocdesc_user_ptr(&desc);
}
