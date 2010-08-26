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
#ifndef _PTHREAD_H_
#define _PTHREAD_H_

#include <time.h>
#include <signal.h>
#include <sched.h>
#include <limits.h>
#include <sys/types.h>

/*
 * Types
 */
typedef struct
{
    int volatile value;
} pthread_mutex_t;

#define  PTHREAD_MUTEX_INITIALIZER             {0}
#define  PTHREAD_RECURSIVE_MUTEX_INITIALIZER   {0x4000}
#define  PTHREAD_ERRORCHECK_MUTEX_INITIALIZER  {0x8000}

enum {
    PTHREAD_MUTEX_NORMAL = 0,
    PTHREAD_MUTEX_RECURSIVE = 1,
    PTHREAD_MUTEX_ERRORCHECK = 2,

    PTHREAD_MUTEX_ERRORCHECK_NP = PTHREAD_MUTEX_ERRORCHECK,
    PTHREAD_MUTEX_RECURSIVE_NP  = PTHREAD_MUTEX_RECURSIVE,

    PTHREAD_MUTEX_DEFAULT = PTHREAD_MUTEX_NORMAL
};



typedef struct
{
    int volatile value;
} pthread_cond_t;

typedef struct
{
    uint32_t flags;
    void * stack_base;
    size_t stack_size;
    size_t guard_size;
    int32_t sched_policy;
    int32_t sched_priority;
} pthread_attr_t;

typedef long pthread_mutexattr_t;
typedef long pthread_condattr_t;

typedef int pthread_key_t;
typedef long pthread_t;

typedef volatile int  pthread_once_t;

/*
 * Defines
 */
#define PTHREAD_COND_INITIALIZER  {0}

#define PTHREAD_STACK_MIN (2 * PAGE_SIZE)

#define PTHREAD_CREATE_DETACHED  0x00000001
#define PTHREAD_CREATE_JOINABLE  0x00000000

#define PTHREAD_ONCE_INIT    0

#define PTHREAD_PROCESS_PRIVATE  0
#define PTHREAD_PROCESS_SHARED   1

#define PTHREAD_SCOPE_SYSTEM     0
#define PTHREAD_SCOPE_PROCESS    1

/*
 * Prototypes
 */
#if __cplusplus
extern "C" {
#endif

int pthread_attr_init(pthread_attr_t * attr);
int pthread_attr_destroy(pthread_attr_t * attr);

int pthread_attr_setdetachstate(pthread_attr_t * attr, int state);
int pthread_attr_getdetachstate(pthread_attr_t const * attr, int * state);

int pthread_attr_setschedpolicy(pthread_attr_t * attr, int policy);
int pthread_attr_getschedpolicy(pthread_attr_t const * attr, int * policy);

int pthread_attr_setschedparam(pthread_attr_t * attr, struct sched_param const * param);
int pthread_attr_getschedparam(pthread_attr_t const * attr, struct sched_param * param);

int pthread_attr_setstacksize(pthread_attr_t * attr, size_t stack_size);
int pthread_attr_getstacksize(pthread_attr_t const * attr, size_t * stack_size);

int pthread_attr_setstackaddr(pthread_attr_t * attr, void * stackaddr);
int pthread_attr_getstackaddr(pthread_attr_t const * attr, void ** stackaddr);

int pthread_attr_setstack(pthread_attr_t * attr, void * stackaddr, size_t stack_size);
int pthread_attr_getstack(pthread_attr_t const * attr, void ** stackaddr, size_t * stack_size);

int pthread_attr_setguardsize(pthread_attr_t * attr, size_t guard_size);
int pthread_attr_getguardsize(pthread_attr_t const * attr, size_t * guard_size);

int pthread_attr_setscope(pthread_attr_t *attr, int  scope);
int pthread_attr_getscope(pthread_attr_t const *attr);

int pthread_getattr_np(pthread_t thid, pthread_attr_t * attr);

int pthread_create(pthread_t *thread, pthread_attr_t const * attr,
                   void *(*start_routine)(void *), void * arg);
void pthread_exit(void * retval);
int pthread_join(pthread_t thid, void ** ret_val);
int pthread_detach(pthread_t  thid);

pthread_t pthread_self(void);
int pthread_equal(pthread_t one, pthread_t two);

int pthread_getschedparam(pthread_t thid, int * policy,
                          struct sched_param * param);
int pthread_setschedparam(pthread_t thid, int poilcy,
                          struct sched_param const * param);

int pthread_mutexattr_init(pthread_mutexattr_t *attr);
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr);
int pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *type);
int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type);
int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int  pshared);
int pthread_mutexattr_getpshared(pthread_mutexattr_t *attr, int *pshared);

int pthread_mutex_init(pthread_mutex_t *mutex,
                       const pthread_mutexattr_t *attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_timedlock(pthread_mutex_t *mutex, struct timespec*  ts);

int pthread_condattr_init(pthread_condattr_t *attr);
int pthread_condattr_getpshared(pthread_condattr_t *attr, int *pshared);
int pthread_condattr_setpshared(pthread_condattr_t* attr, int pshared);
int pthread_condattr_destroy(pthread_condattr_t *attr);

int pthread_cond_init(pthread_cond_t *cond,
                      const pthread_condattr_t *attr);
int pthread_cond_destroy(pthread_cond_t *cond);
int pthread_cond_broadcast(pthread_cond_t *cond);
int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_cond_timedwait(pthread_cond_t *cond,
                           pthread_mutex_t * mutex,
                           const struct timespec *abstime);

/* BIONIC: same as pthread_cond_timedwait, except the 'abstime' given refers
 *         to the CLOCK_MONOTONIC clock instead, to avoid any problems when
 *         the wall-clock time is changed brutally
 */
int pthread_cond_timedwait_monotonic_np(pthread_cond_t         *cond,
                                        pthread_mutex_t        *mutex,
                                        const struct timespec  *abstime);

/* BIONIC: DEPRECATED. same as pthread_cond_timedwait_monotonic_np()
 * unfortunately pthread_cond_timedwait_monotonic has shipped already
 */
int pthread_cond_timedwait_monotonic(pthread_cond_t         *cond,
                                     pthread_mutex_t        *mutex,
                                     const struct timespec  *abstime);

#define HAVE_PTHREAD_COND_TIMEDWAIT_MONOTONIC 1

/* BIONIC: same as pthread_cond_timedwait, except the 'reltime' given refers
 *         is relative to the current time.
 */
int pthread_cond_timedwait_relative_np(pthread_cond_t         *cond,
                                     pthread_mutex_t        *mutex,
                                     const struct timespec  *reltime);

#define HAVE_PTHREAD_COND_TIMEDWAIT_RELATIVE 1



int pthread_cond_timeout_np(pthread_cond_t *cond,
                            pthread_mutex_t * mutex,
                            unsigned msecs);

/* same as pthread_mutex_lock(), but will wait up to 'msecs' milli-seconds
 * before returning. same return values than pthread_mutex_trylock though, i.e.
 * returns EBUSY if the lock could not be acquired after the timeout
 * expired.
 */
int pthread_mutex_lock_timeout_np(pthread_mutex_t *mutex, unsigned msecs);

int pthread_key_create(pthread_key_t *key, void (*destructor_function)(void *));
int pthread_key_delete (pthread_key_t);
int pthread_setspecific(pthread_key_t key, const void *value);
void *pthread_getspecific(pthread_key_t key);

int pthread_kill(pthread_t tid, int sig);
int pthread_sigmask(int how, const sigset_t *set, sigset_t *oset);

int pthread_getcpuclockid(pthread_t  tid, clockid_t  *clockid);

int pthread_once(pthread_once_t  *once_control, void (*init_routine)(void));

int pthread_setname_np(pthread_t thid, const char *thname);

int pthread_atfork(void (*prepare)(void), void (*parent)(void), void(*child)(void));

typedef void  (*__pthread_cleanup_func_t)(void*);

typedef struct __pthread_cleanup_t {
    struct __pthread_cleanup_t*   __cleanup_prev;
    __pthread_cleanup_func_t      __cleanup_routine;
    void*                         __cleanup_arg;
} __pthread_cleanup_t;

extern void  __pthread_cleanup_push(__pthread_cleanup_t*      c,
                                    __pthread_cleanup_func_t  routine,
                                    void*                     arg);

extern void  __pthread_cleanup_pop(__pthread_cleanup_t*  c,
                                   int                   execute);

/* Believe or not, the definitions of pthread_cleanup_push and
 * pthread_cleanup_pop below are correct. Posix states that these
 * can be implemented as macros that might introduce opening and
 * closing braces, and that using setjmp/longjmp/return/break/continue
 * between them results in undefined behaviour.
 *
 * And indeed, GLibc and other C libraries use a similar definition
 */
#define  pthread_cleanup_push(routine, arg)                      \
    do {                                                         \
        __pthread_cleanup_t  __cleanup;                          \
        __pthread_cleanup_push( &__cleanup, (routine), (arg) );  \

#define  pthread_cleanup_pop(execute)                  \
        __pthread_cleanup_pop( &__cleanup, (execute)); \
    } while (0);

#if __cplusplus
} /* extern "C" */
#endif

/************ TO FIX ************/

#define LONG_LONG_MAX __LONG_LONG_MAX__
#define LONG_LONG_MIN (-__LONG_LONG_MAX__ - 1)

#endif // _PTHREAD_H_
