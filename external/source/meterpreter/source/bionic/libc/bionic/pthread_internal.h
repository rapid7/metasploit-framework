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
#ifndef _PTHREAD_INTERNAL_H_
#define _PTHREAD_INTERNAL_H_

#include <pthread.h>

__BEGIN_DECLS

typedef struct pthread_internal_t
{
    struct pthread_internal_t*  next;
    struct pthread_internal_t** pref;
    pthread_attr_t              attr;
    pid_t                       kernel_id;
    pthread_cond_t              join_cond;
    int                         join_count;
    void*                       return_value;
    int                         intern;
    __pthread_cleanup_t*        cleanup_stack;
    void**                      tls;         /* thread-local storage area */
} pthread_internal_t;

extern void _init_thread(pthread_internal_t * thread, pid_t kernel_id, pthread_attr_t * attr, void * stack_base);

/* needed by posix-timers.c */

static __inline__ void timespec_add( struct timespec*  a, const struct timespec*  b )
{
    a->tv_sec  += b->tv_sec;
    a->tv_nsec += b->tv_nsec;
    if (a->tv_nsec >= 1000000000) {
        a->tv_nsec -= 1000000000;
        a->tv_sec  += 1;
    }
}

static  __inline__ void timespec_sub( struct timespec*  a, const struct timespec*  b )
{
    a->tv_sec  -= b->tv_sec;
    a->tv_nsec -= b->tv_nsec;
    if (a->tv_nsec < 0) {
        a->tv_nsec += 1000000000;
        a->tv_sec  -= 1;
    }
}

static  __inline__ void timespec_zero( struct timespec*  a )
{
    a->tv_sec = a->tv_nsec = 0;
}

static  __inline__ int timespec_is_zero( const struct timespec*  a )
{
    return (a->tv_sec == 0 && a->tv_nsec == 0);
}

static  __inline__ int timespec_cmp( const struct timespec*  a, const struct timespec*  b )
{
    if (a->tv_sec  < b->tv_sec)  return -1;
    if (a->tv_sec  > b->tv_sec)  return +1;
    if (a->tv_nsec < b->tv_nsec) return -1;
    if (a->tv_nsec > b->tv_nsec) return +1;
    return 0;
}

static  __inline__ int timespec_cmp0( const struct timespec*  a )
{
    if (a->tv_sec < 0) return -1;
    if (a->tv_sec > 0) return +1;
    if (a->tv_nsec < 0) return -1;
    if (a->tv_nsec > 0) return +1;
    return 0;
}

extern int  __pthread_cond_timedwait(pthread_cond_t*, 
                                     pthread_mutex_t*,
                                     const struct timespec*, 
                                     clockid_t);

extern int  __pthread_cond_timedwait_relative(pthread_cond_t*,
                                              pthread_mutex_t*,
                                              const struct timespec*);

/* needed by fork.c */
extern void __timer_table_start_stop(int  stop);
extern void __bionic_atfork_run_prepare();
extern void __bionic_atfork_run_child();
extern void __bionic_atfork_run_parent();

__END_DECLS

#endif /* _PTHREAD_INTERNAL_H_ */
