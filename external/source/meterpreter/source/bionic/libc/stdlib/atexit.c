/*	$OpenBSD: atexit.c,v 1.14 2007/09/05 20:47:47 chl Exp $ */
/*
 * Copyright (c) 2002 Daniel Hartmeier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "atexit.h"
#include "thread_private.h"

int __atexit_invalid = 1;
struct atexit *__atexit;

/*
 * Function pointers are stored in a linked list of pages. The list
 * is initially empty, and pages are allocated on demand. The first
 * function pointer in the first allocated page (the last one in
 * the linked list) is reserved for the cleanup function.
 *
 * Outside the following functions, all pages are mprotect()'ed
 * to prevent unintentional/malicious corruption.
 */

/*
 * Register a function to be performed at exit or when a shared object
 * with the given dso handle is unloaded dynamically.  Also used as
 * the backend for atexit().  For more info on this API, see:
 *
 *	http://www.codesourcery.com/cxx-abi/abi.html#dso-dtor
 */
int
__cxa_atexit(void (*func)(void *), void *arg, void *dso)
{
	struct atexit *p = __atexit;
	struct atexit_fn *fnp;
	int pgsize = getpagesize();
	int ret = -1;

	if (pgsize < (int)sizeof(*p))
		return (-1);
	_ATEXIT_LOCK();
	p = __atexit;
	if (p != NULL) {
		if (p->ind + 1 >= p->max)
			p = NULL;
		else if (mprotect(p, pgsize, PROT_READ | PROT_WRITE))
			goto unlock;
	}
	if (p == NULL) {
		p = mmap(NULL, pgsize, PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_PRIVATE, -1, 0);
		if (p == MAP_FAILED)
			goto unlock;
		if (__atexit == NULL) {
			memset(&p->fns[0], 0, sizeof(p->fns[0]));
			p->ind = 1;
		} else
			p->ind = 0;
		p->max = (pgsize - ((char *)&p->fns[0] - (char *)p)) /
		    sizeof(p->fns[0]);
		p->next = __atexit;
		__atexit = p;
		if (__atexit_invalid)
			__atexit_invalid = 0;
	}
	fnp = &p->fns[p->ind++];
	fnp->fn_ptr.cxa_func = func;
	fnp->fn_arg = arg;
	fnp->fn_dso = dso;
	if (mprotect(p, pgsize, PROT_READ))
		goto unlock;
	ret = 0;
unlock:
	_ATEXIT_UNLOCK();
	return (ret);
}

/*
 * Register a function to be performed at exit.
 */
int
atexit(void (*func)(void))
{
	return (__cxa_atexit((void (*)(void *))func, NULL, NULL));
}

/*
 * Call all handlers registered with __cxa_atexit() for the shared
 * object owning 'dso'.
 * Note: if 'dso' is NULL, then all remaining handlers are called.
 */
void
__cxa_finalize(void *dso)
{
	struct atexit *p, *q;
	struct atexit_fn fn;
	int n, pgsize = getpagesize();
	static int call_depth;

	if (__atexit_invalid)
		return;

	call_depth++;

	for (p = __atexit; p != NULL; p = p->next) {
		for (n = p->ind; --n >= 0;) {
			if (p->fns[n].fn_ptr.cxa_func == NULL)
				continue;	/* already called */
			if (dso != NULL && dso != p->fns[n].fn_dso)
				continue;	/* wrong DSO */

			/*
			 * Mark handler as having been already called to avoid
			 * dupes and loops, then call the appropriate function.
			 */
			fn = p->fns[n];
			if (mprotect(p, pgsize, PROT_READ | PROT_WRITE) == 0) {
				p->fns[n].fn_ptr.cxa_func = NULL;
				mprotect(p, pgsize, PROT_READ);
			}
#if ANDROID
                        /* it looks like we should always call the function
                         * with an argument, even if dso is not NULL. Otherwise
                         * static destructors will not be called properly on
                         * the ARM.
                         */
                        (*fn.fn_ptr.cxa_func)(fn.fn_arg);
#else /* !ANDROID */
			if (dso != NULL)
				(*fn.fn_ptr.cxa_func)(fn.fn_arg);
			else
				(*fn.fn_ptr.std_func)();
#endif /* !ANDROID */
		}
	}

	/*
	 * If called via exit(), unmap the pages since we have now run
	 * all the handlers.  We defer this until calldepth == 0 so that
	 * we don't unmap things prematurely if called recursively.
	 */
	if (dso == NULL && --call_depth == 0) {
		for (p = __atexit; p != NULL; ) {
			q = p;
			p = p->next;
			munmap(q, pgsize);
		}
		__atexit = NULL;
	}
}

/*
 * Register the cleanup function
 */
void
__atexit_register_cleanup(void (*func)(void))
{
	struct atexit *p;
	int pgsize = getpagesize();

	if (pgsize < (int)sizeof(*p))
		return;
	_ATEXIT_LOCK();
	p = __atexit;
	while (p != NULL && p->next != NULL)
		p = p->next;
	if (p == NULL) {
		p = mmap(NULL, pgsize, PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_PRIVATE, -1, 0);
		if (p == MAP_FAILED)
			goto unlock;
		p->ind = 1;
		p->max = (pgsize - ((char *)&p->fns[0] - (char *)p)) /
		    sizeof(p->fns[0]);
		p->next = NULL;
		__atexit = p;
		if (__atexit_invalid)
			__atexit_invalid = 0;
	} else {
		if (mprotect(p, pgsize, PROT_READ | PROT_WRITE))
			goto unlock;
	}
	p->fns[0].fn_ptr.std_func = func;
	p->fns[0].fn_arg = NULL;
	p->fns[0].fn_dso = NULL;
	mprotect(p, pgsize, PROT_READ);
unlock:
	_ATEXIT_UNLOCK();
}
