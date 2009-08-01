/*-
 * Copyright 1999, 2000 John D. Polstra.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *	from: FreeBSD: src/libexec/rtld-elf/sparc64/lockdflt.c,v 1.3 2002/10/09
 * $FreeBSD: head/libexec/rtld-elf/rtld_lock.c 191303 2009-04-20 10:35:50Z rwatson $
 */

/*
 * Thread locking implementation for the dynamic linker.
 *
 * We use the "simple, non-scalable reader-preference lock" from:
 *
 *   J. M. Mellor-Crummey and M. L. Scott. "Scalable Reader-Writer
 *   Synchronization for Shared-Memory Multiprocessors." 3rd ACM Symp. on
 *   Principles and Practice of Parallel Programming, April 1991.
 *
 * In this algorithm the lock is a single word.  Its low-order bit is
 * set when a writer holds the lock.  The remaining high-order bits
 * contain a count of readers desiring the lock.  The algorithm requires
 * atomic "compare_and_store" and "add" operations, which we implement
 * using assembly language sequences in "rtld_start.S".
 */

#include <sys/param.h>

#include <signal.h>
#include <stdlib.h>
#include <time.h>

#include "debug.h"
#include "rtld.h"
#include "rtld_machdep.h"

#define WAFLAG		0x1	/* A writer holds the lock */
#define RC_INCR		0x2	/* Adjusts count of readers desiring lock */

typedef struct Struct_Lock {
	volatile u_int lock;
	void *base;
} Lock;

static sigset_t fullsigmask, oldsigmask;
static int thread_flag;

static void *
def_lock_create()
{
    void *base;
    char *p;
    uintptr_t r;
    Lock *l;

    /*
     * Arrange for the lock to occupy its own cache line.  First, we
     * optimistically allocate just a cache line, hoping that malloc
     * will give us a well-aligned block of memory.  If that doesn't
     * work, we allocate a larger block and take a well-aligned cache
     * line from it.
     */
    base = xmalloc(CACHE_LINE_SIZE);
    p = (char *)base;
    if ((uintptr_t)p % CACHE_LINE_SIZE != 0) {
	free(base);
	base = xmalloc(2 * CACHE_LINE_SIZE);
	p = (char *)base;
	if ((r = (uintptr_t)p % CACHE_LINE_SIZE) != 0)
	    p += CACHE_LINE_SIZE - r;
    }
    l = (Lock *)p;
    l->base = base;
    l->lock = 0;
    return l;
}

static void
def_lock_destroy(void *lock)
{
    Lock *l = (Lock *)lock;

    free(l->base);
}

static void
def_rlock_acquire(void *lock)
{
    Lock *l = (Lock *)lock;

    atomic_add_acq_int(&l->lock, RC_INCR);
    while (l->lock & WAFLAG)
	    ;	/* Spin */
}

static void
def_wlock_acquire(void *lock)
{
    Lock *l = (Lock *)lock;
    sigset_t tmp_oldsigmask;

    for ( ; ; ) {
	sigprocmask(SIG_BLOCK, &fullsigmask, &tmp_oldsigmask);
	if (atomic_cmpset_acq_int(&l->lock, 0, WAFLAG))
	    break;
	sigprocmask(SIG_SETMASK, &tmp_oldsigmask, NULL);
    }
    oldsigmask = tmp_oldsigmask;
}

static void
def_lock_release(void *lock)
{
    Lock *l = (Lock *)lock;

    if ((l->lock & WAFLAG) == 0)
    	atomic_add_rel_int(&l->lock, -RC_INCR);
    else {
    	atomic_add_rel_int(&l->lock, -WAFLAG);
    	sigprocmask(SIG_SETMASK, &oldsigmask, NULL);
    }
}

static int
def_thread_set_flag(int mask)
{
	int old_val = thread_flag;
	thread_flag |= mask;
	return (old_val);
}

static int
def_thread_clr_flag(int mask)
{
	int old_val = thread_flag;
	thread_flag &= ~mask;
	return (old_val);
}

/*
 * Public interface exposed to the rest of the dynamic linker.
 */
static struct RtldLockInfo lockinfo;
static struct RtldLockInfo deflockinfo;

static __inline int
thread_mask_set(int mask)
{
	return lockinfo.thread_set_flag(mask);
}

static __inline void
thread_mask_clear(int mask)
{
	lockinfo.thread_clr_flag(mask);
}

#define	RTLD_LOCK_CNT	3
struct rtld_lock {
	void	*handle;
	int	 mask;
} late_rtld_locks[RTLD_LOCK_CNT];

rtld_lock_t	late_rtld_bind_lock = &late_rtld_locks[0];
rtld_lock_t	late_rtld_libc_lock = &late_rtld_locks[1];
rtld_lock_t	late_rtld_phdr_lock = &late_rtld_locks[2];

int
rlock_acquire(rtld_lock_t lock)
{
	if (thread_mask_set(lock->mask) & lock->mask) {
	    dbg("rlock_acquire: recursed");
	    return (0);
	}
	lockinfo.rlock_acquire(lock->handle);
	return (1);
}

int
wlock_acquire(rtld_lock_t lock)
{
	if (thread_mask_set(lock->mask) & lock->mask) {
	    dbg("wlock_acquire: recursed");
	    return (0);
	}
	lockinfo.wlock_acquire(lock->handle);
	return (1);
}

void
rlock_release(rtld_lock_t lock, int locked)
{
	if (locked == 0)
	    return;
	thread_mask_clear(lock->mask);
	lockinfo.lock_release(lock->handle);
}

void
wlock_release(rtld_lock_t lock, int locked)
{
	if (locked == 0)
	    return;
	thread_mask_clear(lock->mask);
	lockinfo.lock_release(lock->handle);
}

void
late_lockdflt_init()
{
    int i;

    deflockinfo.rtli_version  = RTLI_VERSION;
    deflockinfo.lock_create   = def_lock_create;
    deflockinfo.lock_destroy  = def_lock_destroy;
    deflockinfo.rlock_acquire = def_rlock_acquire;
    deflockinfo.wlock_acquire = def_wlock_acquire;
    deflockinfo.lock_release  = def_lock_release;
    deflockinfo.thread_set_flag = def_thread_set_flag;
    deflockinfo.thread_clr_flag = def_thread_clr_flag;
    deflockinfo.at_fork = NULL;

    for (i = 0; i < RTLD_LOCK_CNT; i++) {
	    late_rtld_locks[i].mask   = (1 << i);
	    late_rtld_locks[i].handle = NULL;
    }

    memcpy(&lockinfo, &deflockinfo, sizeof(lockinfo));
    _late_rtld_thread_init(NULL);
    /*
     * Construct a mask to block all signals except traps which might
     * conceivably be generated within the dynamic linker itself.
     */
    _sigfillset(&fullsigmask);
    _sigdelset(&fullsigmask, SIGILL);
    _sigdelset(&fullsigmask, SIGTRAP);
    _sigdelset(&fullsigmask, SIGABRT);
    _sigdelset(&fullsigmask, SIGEMT);
    _sigdelset(&fullsigmask, SIGFPE);
    _sigdelset(&fullsigmask, SIGBUS);
    _sigdelset(&fullsigmask, SIGSEGV);
    _sigdelset(&fullsigmask, SIGSYS);
}

/*
 * Callback function to allow threads implementation to
 * register their own locking primitives if the default
 * one is not suitable.
 * The current context should be the only context
 * executing at the invocation time.
 */
void
_late_rtld_thread_init(struct RtldLockInfo *pli)
{
	int flags, i;
	void *locks[RTLD_LOCK_CNT];

	/* disable all locking while this function is running */
	flags =	thread_mask_set(~0);

	if (pli == NULL)
		pli = &deflockinfo;


	for (i = 0; i < RTLD_LOCK_CNT; i++)
		if ((locks[i] = pli->lock_create()) == NULL)
			break;

	if (i < RTLD_LOCK_CNT) {
		while (--i >= 0)
			pli->lock_destroy(locks[i]);
		abort();
	}

	for (i = 0; i < RTLD_LOCK_CNT; i++) {
		if (late_rtld_locks[i].handle == NULL)
			continue;
		if (flags & late_rtld_locks[i].mask)
			lockinfo.lock_release(late_rtld_locks[i].handle);
		lockinfo.lock_destroy(late_rtld_locks[i].handle);
	}

	for (i = 0; i < RTLD_LOCK_CNT; i++) {
		late_rtld_locks[i].handle = locks[i];
		if (flags & late_rtld_locks[i].mask)
			pli->wlock_acquire(late_rtld_locks[i].handle);
	}

	lockinfo.lock_create = pli->lock_create;
	lockinfo.lock_destroy = pli->lock_destroy;
	lockinfo.rlock_acquire = pli->rlock_acquire;
	lockinfo.wlock_acquire = pli->wlock_acquire;
	lockinfo.lock_release  = pli->lock_release;
	lockinfo.thread_set_flag = pli->thread_set_flag;
	lockinfo.thread_clr_flag = pli->thread_clr_flag;
	lockinfo.at_fork = pli->at_fork;

	/* restore thread locking state, this time with new locks */
	thread_mask_clear(~0);
	thread_mask_set(flags);
	dbg("_rtld_thread_init: done");
}

void
_late_rtld_atfork_pre(int *locks)
{

	locks[2] = wlock_acquire(late_rtld_phdr_lock);
	locks[0] = rlock_acquire(late_rtld_bind_lock);
}

void
_late_rtld_atfork_post(int *locks)
{

	rlock_release(late_rtld_bind_lock, locks[0]);
	wlock_release(late_rtld_phdr_lock, locks[2]);
}
