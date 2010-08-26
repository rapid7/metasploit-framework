/*	$OpenBSD: abort.c,v 1.14 2005/08/08 08:05:36 espie Exp $ */
/*
 * Copyright (c) 1985 Regents of the University of California.
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
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "thread_private.h"
#include "atexit.h"

/* temporary, for bug hunting */
#include "logd.h"
#define debug_log(format, ...)  \
    __libc_android_log_print(ANDROID_LOG_DEBUG, "libc-abort", (format), ##__VA_ARGS__ )

#ifdef __arm__
void
__libc_android_abort(void)
#else
void
abort(void)
#endif
{
	struct atexit *p = __atexit;
	static int cleanup_called = 0;
	sigset_t mask;

  
	sigfillset(&mask);
	/*
	 * don't block SIGABRT to give any handler a chance; we ignore
	 * any errors -- X311J doesn't allow abort to return anyway.
	 */
	sigdelset(&mask, SIGABRT);
    /* temporary, so deliberate seg fault can be caught by debuggerd */
	sigdelset(&mask, SIGSEGV);
    /* -- */
	(void)sigprocmask(SIG_SETMASK, &mask, (sigset_t *)NULL);

	/*
	 * POSIX requires we flush stdio buffers on abort
	 */
	if (cleanup_called == 0) {
		while (p != NULL && p->next != NULL)
			p = p->next;
		/* the check for fn_dso == NULL is mostly paranoia */
		if (p != NULL && p->fns[0].fn_dso == NULL &&
		    p->fns[0].fn_ptr.std_func != NULL) {
			cleanup_called = 1;
			(*p->fns[0].fn_ptr.std_func)();
		}
	}

    /* temporary, for bug hunting */
    /* seg fault seems to produce better debuggerd results than SIGABRT */
    *((char*)0xdeadbaad) = 39;
    /* -- */

	(void)kill(getpid(), SIGABRT);

	/*
	 * if SIGABRT ignored, or caught and the handler returns, do
	 * it again, only harder.
	 */
        {
            struct sigaction sa;

            sa.sa_handler = SIG_DFL;
            sa.sa_flags   = SA_RESTART;
            sigemptyset(&sa.sa_mask);

            (void)sigaction( SIGABRT, &sa, &sa );
        }

	(void)sigprocmask(SIG_SETMASK, &mask, (sigset_t *)NULL);
	(void)kill(getpid(), SIGABRT);
	_exit(1);
}

#ifdef __arm__
/*
 * abort() does not return, which gcc interprets to mean that it doesn't
 * need to preserve any of the callee-save registers.  Unfortunately this
 * includes the link register, so if LR is used there is no way to determine
 * which function called abort().
 *
 * We work around this by inserting a trivial stub that doesn't alter
 * any of the "interesting" registers and thus doesn't need to save them.
 * We can't just call __libc_android_abort from C because gcc uses "bl"
 * without first saving LR, so we use an asm statement.  This also has
 * the side-effect of replacing abort() with __libc_android_abort() in
 * the stack trace.
 *
 * Ideally __libc_android_abort would be static, but I haven't figured out
 * how to tell gcc to call a static function from an asm statement.
 */
void
abort(void)
{
    asm ("b __libc_android_abort");
    _exit(1);       /* suppress gcc noreturn warnings */
}
#endif

