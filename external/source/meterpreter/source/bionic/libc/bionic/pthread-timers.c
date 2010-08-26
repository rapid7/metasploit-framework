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
#include "pthread_internal.h"
#include <linux/time.h>
#include <string.h>
#include <errno.h>

/* This file implements the support required to implement SIGEV_THREAD posix 
 * timers. See the following pages for additionnal details:
 *
 * www.opengroup.org/onlinepubs/000095399/functions/timer_create.html
 * www.opengroup.org/onlinepubs/000095399/functions/timer_settime.html
 * www.opengroup.org/onlinepubs/000095399/functions/xsh_chap02_04.html#tag_02_04_01
 *
 * The Linux kernel doesn't support these, so we need to implement them in the
 * C library. We use a very basic scheme where each timer is associated to a
 * thread that will loop, waiting for timeouts or messages from the program
 * corresponding to calls to timer_settime() and timer_delete().
 *
 * Note also an important thing: Posix mandates that in the case of fork(),
 * the timers of the child process should be disarmed, but not deleted.
 * this is implemented by providing a fork() wrapper (see bionic/fork.c) which
 * stops all timers before the fork, and only re-start them in case of error
 * or in the parent process.
 *
 * the stop/start is implemented by the __timer_table_start_stop() function
 * below.
 */

/* normal (i.e. non-SIGEV_THREAD) timer ids are created directly by the kernel
 * and are passed as is to/from the caller.
 *
 * on the other hand, a SIGEV_THREAD timer ID will have its TIMER_ID_WRAP_BIT
 * always set to 1. In this implementation, this is always bit 31, which is
 * guaranteed to never be used by kernel-provided timer ids
 *
 * (see code in <kernel>/lib/idr.c, used to manage IDs, to see why)
 */

#define  TIMER_ID_WRAP_BIT        0x80000000
#define  TIMER_ID_WRAP(id)        ((timer_t)((id) |  TIMER_ID_WRAP_BIT))
#define  TIMER_ID_UNWRAP(id)      ((timer_t)((id) & ~TIMER_ID_WRAP_BIT))
#define  TIMER_ID_IS_WRAPPED(id)  (((id) & TIMER_ID_WRAP_BIT) != 0)

/* this value is used internally to indicate a 'free' or 'zombie' 
 * thr_timer structure. Here, 'zombie' means that timer_delete()
 * has been called, but that the corresponding thread hasn't
 * exited yet.
 */
#define  TIMER_ID_NONE            ((timer_t)0xffffffff)

/* True iff a timer id is valid */
#define  TIMER_ID_IS_VALID(id)    ((id) != TIMER_ID_NONE)

/* the maximum value of overrun counters */
#define  DELAYTIMER_MAX    0x7fffffff

#define  __likely(x)   __builtin_expect(!!(x),1)
#define  __unlikely(x) __builtin_expect(!!(x),0)

typedef struct thr_timer          thr_timer_t;
typedef struct thr_timer_table    thr_timer_table_t;

/* The Posix spec says the function receives an unsigned parameter, but
 * it's really a 'union sigval' a.k.a. sigval_t */
typedef void (*thr_timer_func_t)( sigval_t );

struct thr_timer {
    thr_timer_t*       next;     /* next in free list */
    timer_t            id;       /* TIMER_ID_NONE iff free or dying */
    clockid_t          clock;
    pthread_t          thread;
    pthread_attr_t     attributes;
    thr_timer_func_t   callback;
    sigval_t           value;

    /* the following are used to communicate between
     * the timer thread and the timer_XXX() functions
     */
    pthread_mutex_t           mutex;     /* lock */
    pthread_cond_t            cond;      /* signal a state change to thread */
    int volatile              done;      /* set by timer_delete */
    int volatile              stopped;   /* set by _start_stop() */
    struct timespec volatile  expires;   /* next expiration time, or 0 */
    struct timespec volatile  period;    /* reload value, or 0 */
    int volatile              overruns;  /* current number of overruns */
};

#define  MAX_THREAD_TIMERS  32

struct thr_timer_table {
    pthread_mutex_t  lock;
    thr_timer_t*     free_timer;
    thr_timer_t      timers[ MAX_THREAD_TIMERS ];
};

/** GLOBAL TABLE OF THREAD TIMERS
 **/

static void
thr_timer_table_init( thr_timer_table_t*  t )
{
    int  nn;

    memset(t, 0, sizeof *t);
    pthread_mutex_init( &t->lock, NULL );

    for (nn = 0; nn < MAX_THREAD_TIMERS; nn++)
        t->timers[nn].id = TIMER_ID_NONE;

    t->free_timer = &t->timers[0];
    for (nn = 1; nn < MAX_THREAD_TIMERS; nn++)
        t->timers[nn-1].next = &t->timers[nn];
}


static thr_timer_t*
thr_timer_table_alloc( thr_timer_table_t*  t )
{
    thr_timer_t*  timer;

    if (t == NULL)
        return NULL;

    pthread_mutex_lock(&t->lock);
    timer = t->free_timer;
    if (timer != NULL) {
        t->free_timer = timer->next;
        timer->next   = NULL;
        timer->id     = TIMER_ID_WRAP((timer - t->timers));
    }
    pthread_mutex_unlock(&t->lock);
    return timer;
}


static void
thr_timer_table_free( thr_timer_table_t*  t, thr_timer_t*  timer )
{
    pthread_mutex_lock( &t->lock );
    timer->id     = TIMER_ID_NONE;
    timer->thread = 0;
    timer->next   = t->free_timer;
    t->free_timer = timer;
    pthread_mutex_unlock( &t->lock );
}


static void
thr_timer_table_start_stop( thr_timer_table_t*  t, int  stop )
{
    int  nn;

    pthread_mutex_lock(&t->lock);

    for (nn = 0; nn < MAX_THREAD_TIMERS; nn++) {
        thr_timer_t*  timer  = &t->timers[nn];

        if (TIMER_ID_IS_VALID(timer->id)) {
            /* tell the thread to start/stop */
            pthread_mutex_lock(&timer->mutex);
            timer->stopped = stop;
            pthread_cond_signal( &timer->cond );
            pthread_mutex_unlock(&timer->mutex);
        }
    }
    pthread_mutex_unlock(&t->lock);
}


/* convert a timer_id into the corresponding thr_timer_t* pointer
 * returns NULL if the id is not wrapped or is invalid/free
 */
static thr_timer_t*
thr_timer_table_from_id( thr_timer_table_t*  t,
                         timer_t             id,
                         int                 remove )
{
    unsigned      index;
    thr_timer_t*  timer;

    if (t == NULL || !TIMER_ID_IS_WRAPPED(id))
        return NULL;

    index = (unsigned) TIMER_ID_UNWRAP(id);
    if (index >= MAX_THREAD_TIMERS)
        return NULL;

    pthread_mutex_lock(&t->lock);

    timer = &t->timers[index];

    if (!TIMER_ID_IS_VALID(timer->id)) {
        timer = NULL;
    } else {
        /* if we're removing this timer, clear the id
         * right now to prevent another thread to
         * use the same id after the unlock */
        if (remove)
            timer->id = TIMER_ID_NONE;
    }
    pthread_mutex_unlock(&t->lock);

    return timer;
}

/* the static timer table - we only create it if the process
 * really wants to use SIGEV_THREAD timers, which should be
 * pretty infrequent
 */

static pthread_once_t      __timer_table_once = PTHREAD_ONCE_INIT;
static thr_timer_table_t*  __timer_table;

static void
__timer_table_init( void )
{
    __timer_table = calloc(1,sizeof(*__timer_table));

    if (__timer_table != NULL)
        thr_timer_table_init( __timer_table );
}

static thr_timer_table_t*
__timer_table_get(void)
{
    pthread_once( &__timer_table_once, __timer_table_init );
    return __timer_table;
}

/** POSIX THREAD TIMERS CLEANUP ON FORK
 **
 ** this should be called from the 'fork()' wrapper to stop/start
 ** all active thread timers. this is used to implement a Posix
 ** requirements: the timers of fork child processes must be
 ** disarmed but not deleted.
 **/
void
__timer_table_start_stop( int  stop )
{
    if (__timer_table != NULL) {
        thr_timer_table_t*  table = __timer_table_get();
        thr_timer_table_start_stop(table, stop);
    }
}

static thr_timer_t*
thr_timer_from_id( timer_t   id )
{
    thr_timer_table_t*  table = __timer_table_get();
    thr_timer_t*        timer = thr_timer_table_from_id( table, id, 0 );

    return timer;
}


static __inline__ void
thr_timer_lock( thr_timer_t*  t )
{
    pthread_mutex_lock(&t->mutex);
}

static __inline__ void
thr_timer_unlock( thr_timer_t*  t )
{
    pthread_mutex_unlock(&t->mutex);
}

/** POSIX TIMERS APIs */

/* first, declare the syscall stubs */
extern int __timer_create( clockid_t, struct sigevent*, timer_t* );
extern int __timer_delete( timer_t );
extern int __timer_gettime( timer_t, struct itimerspec* );
extern int __timer_settime( timer_t, int, const struct itimerspec*, struct itimerspec* );
extern int __timer_getoverrun(timer_t);

static void*  timer_thread_start( void* );

/* then the wrappers themselves */
int
timer_create( clockid_t  clockid, struct sigevent*  evp, timer_t  *ptimerid)
{
    /* if not a SIGEV_THREAD timer, direct creation by the kernel */
    if (__likely(evp == NULL || evp->sigev_notify != SIGEV_THREAD))
        return __timer_create( clockid, evp, ptimerid );

    // check arguments
    if (evp->sigev_notify_function == NULL) {
        errno = EINVAL;
        return -1;
    }

    {
        struct timespec  dummy;

        /* check that the clock id is supported by the kernel */
        if (clock_gettime( clockid, &dummy ) < 0 && errno == EINVAL )
            return -1;
    }

    /* create a new timer and its thread */
    {
        thr_timer_table_t*  table = __timer_table_get();
        thr_timer_t*        timer = thr_timer_table_alloc( table );
        struct sigevent     evp0;

        if (timer == NULL) {
            errno = ENOMEM;
            return -1;
        }

        /* copy the thread attributes */
        if (evp->sigev_notify_attributes == NULL) {
            pthread_attr_init(&timer->attributes);
        }
        else {
            timer->attributes = ((pthread_attr_t*)evp->sigev_notify_attributes)[0];
        }

        /* Posix says that the default is PTHREAD_CREATE_DETACHED and
         * that PTHREAD_CREATE_JOINABLE has undefined behaviour.
         * So simply always use DETACHED :-)
         */
        pthread_attr_setdetachstate(&timer->attributes, PTHREAD_CREATE_DETACHED);

        timer->callback = evp->sigev_notify_function;
        timer->value    = evp->sigev_value;
        timer->clock    = clockid;

        pthread_mutex_init( &timer->mutex, NULL );
        pthread_cond_init( &timer->cond, NULL );

        timer->done           = 0;
        timer->stopped        = 0;
        timer->expires.tv_sec = timer->expires.tv_nsec = 0;
        timer->period.tv_sec  = timer->period.tv_nsec  = 0;
        timer->overruns       = 0;

        /* create the thread */
        if (pthread_create( &timer->thread, &timer->attributes, timer_thread_start, timer ) < 0) {
            thr_timer_table_free( __timer_table, timer );
            errno = ENOMEM;
            return -1;
        }

        *ptimerid = timer->id;
        return 0;
    }
}


int
timer_delete( timer_t  id )
{
    if ( __likely(!TIMER_ID_IS_WRAPPED(id)) )
        return __timer_delete( id );
    else
    {
        thr_timer_table_t*  table = __timer_table_get();
        thr_timer_t*        timer = thr_timer_table_from_id(table, id, 1);

        if (timer == NULL) {
            errno = EINVAL;
            return -1;
        }

        /* tell the timer's thread to stop */
        thr_timer_lock(timer);
        timer->done = 1;
        pthread_cond_signal( &timer->cond );
        thr_timer_unlock(timer);

        /* NOTE: the thread will call __timer_table_free() to free the
         * timer object. the '1' parameter to thr_timer_table_from_id
         * above ensured that the object and its timer_id cannot be
         * reused before that.
         */
        return 0;
    }
}

/* return the relative time until the next expiration, or 0 if
 * the timer is disarmed */
static void
timer_gettime_internal( thr_timer_t*        timer,
                        struct itimerspec*  spec)
{
    struct timespec  diff;

    diff = timer->expires;
    if (!timespec_is_zero(&diff)) 
    {
        struct timespec  now;

        clock_gettime( timer->clock, &now );
        timespec_sub(&diff, &now);

        /* in case of overrun, return 0 */
        if (timespec_cmp0(&diff) < 0) {
            timespec_zero(&diff);
        }
    }

    spec->it_value    = diff;
    spec->it_interval = timer->period;
}


int
timer_gettime( timer_t  id, struct itimerspec*  ospec )
{
    if (ospec == NULL) {
        errno = EINVAL;
        return -1;
    }

    if ( __likely(!TIMER_ID_IS_WRAPPED(id)) ) {
        return __timer_gettime( id, ospec );
    } else {
        thr_timer_t*  timer = thr_timer_from_id(id);

        if (timer == NULL) {
            errno = EINVAL;
            return -1;
        }
        thr_timer_lock(timer);
        timer_gettime_internal( timer, ospec );
        thr_timer_unlock(timer);
    }
    return 0;
}


int
timer_settime( timer_t                   id,
               int                       flags,
               const struct itimerspec*  spec,
               struct itimerspec*        ospec )
{
    if (spec == NULL) {
        errno = EINVAL;
        return -1;
    }

    if ( __likely(!TIMER_ID_IS_WRAPPED(id)) ) {
        return __timer_settime( id, flags, spec, ospec );
    } else {
        thr_timer_t*        timer = thr_timer_from_id(id);
        struct timespec     expires, now;

        if (timer == NULL) {
            errno = EINVAL;
            return -1;
        }
        thr_timer_lock(timer);

        /* return current timer value if ospec isn't NULL */
        if (ospec != NULL) {
            timer_gettime_internal(timer, ospec );
        }

        /* compute next expiration time. note that if the
         * new it_interval is 0, we should disarm the timer
         */
        expires = spec->it_value;
        if (!timespec_is_zero(&expires)) {
            clock_gettime( timer->clock, &now );
            if (!(flags & TIMER_ABSTIME)) {
                timespec_add(&expires, &now);
            } else {
                if (timespec_cmp(&expires, &now) < 0)
                    expires = now;
            }
        }
        timer->expires = expires;
        timer->period  = spec->it_interval;
        thr_timer_unlock( timer );

        /* signal the change to the thread */
        pthread_cond_signal( &timer->cond );
    }
    return 0;
}


int
timer_getoverrun(timer_t  id)
{
    if ( __likely(!TIMER_ID_IS_WRAPPED(id)) ) {
        return __timer_getoverrun( id );
    } else {
        thr_timer_t*  timer = thr_timer_from_id(id);
        int           result;

        if (timer == NULL) {
            errno = EINVAL;
            return -1;
        }

        thr_timer_lock(timer);
        result = timer->overruns;
        thr_timer_unlock(timer);

        return result;
    }
}


static void*
timer_thread_start( void*  _arg )
{
    thr_timer_t*  timer = _arg;

    thr_timer_lock( timer );

    /* we loop until timer->done is set in timer_delete() */
    while (!timer->done) 
    {
        struct timespec   expires = timer->expires;
        struct timespec   period  = timer->period;
        struct timespec   now;

        /* if the timer is stopped or disarmed, wait indefinitely
         * for a state change from timer_settime/_delete/_start_stop
         */
        if ( timer->stopped || timespec_is_zero(&expires) )
        {
            pthread_cond_wait( &timer->cond, &timer->mutex );
            continue;
        }

        /* otherwise, we need to do a timed wait until either a
        * state change of the timer expiration time.
        */
        clock_gettime(timer->clock, &now);

        if (timespec_cmp( &expires, &now ) > 0)
        {
            /* cool, there was no overrun, so compute the
             * relative timeout as 'expires - now', then wait
             */
            int              ret;
            struct timespec  diff = expires;
            timespec_sub( &diff, &now );

            ret = __pthread_cond_timedwait_relative(
                        &timer->cond, &timer->mutex, &diff);

            /* if we didn't timeout, it means that a state change
                * occured, so reloop to take care of it.
                */
            if (ret != ETIMEDOUT)
                continue;
        }
        else
        {
            /* overrun was detected before we could wait ! */
            if (!timespec_is_zero( &period ) )
            {
                /* for periodic timers, compute total overrun count */
                do {
                    timespec_add( &expires, &period );
                    if (timer->overruns < DELAYTIMER_MAX)
                        timer->overruns += 1;
                } while ( timespec_cmp( &expires, &now ) < 0 );

                /* backtrack the last one, because we're going to
                 * add the same value just a bit later */
                timespec_sub( &expires, &period );
            }
            else
            {
                /* for non-periodic timer, things are simple */
                timer->overruns = 1;
            }
        }

        /* if we get there, a timeout was detected.
         * first reload/disarm the timer has needed
         */
        if ( !timespec_is_zero(&period) ) {
            timespec_add( &expires, &period );
        } else {
            timespec_zero( &expires );
        }
        timer->expires = expires;

        /* now call the timer callback function. release the
         * lock to allow the function to modify the timer setting
         * or call timer_getoverrun().
         *
         * NOTE: at this point we trust the callback not to be a
         *       total moron and pthread_kill() the timer thread
         */
        thr_timer_unlock(timer);
        timer->callback( timer->value );
        thr_timer_lock(timer);

        /* now clear the overruns counter. it only makes sense
         * within the callback */
        timer->overruns = 0;
    }

    thr_timer_unlock( timer );

    /* free the timer object now. there is no need to call
     * __timer_table_get() since we're guaranteed that __timer_table
     * is initialized in this thread
     */
    thr_timer_table_free(__timer_table, timer);

    return NULL;
}
