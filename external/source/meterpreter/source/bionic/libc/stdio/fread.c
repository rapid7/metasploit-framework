/*	$OpenBSD: fread.c,v 1.6 2005/08/08 08:05:36 espie Exp $ */
/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "local.h"

static int
lflush(FILE *fp)
{

    if ((fp->_flags & (__SLBF|__SWR)) == (__SLBF|__SWR))
        return (__sflush(fp));
    return (0);
}

size_t
fread(void *buf, size_t size, size_t count, FILE *fp)
{
    size_t resid;
    char *p;
    int r;
    size_t total;

    /*
     * The ANSI standard requires a return value of 0 for a count
     * or a size of 0.  Peculiarily, it imposes no such requirements
     * on fwrite; it only requires fread to be broken.
     */
    if ((resid = count * size) == 0)
        return (0);
    if (fp->_r < 0)
        fp->_r = 0;
    total = resid;
    p = buf;

#if 1  /* BIONIC: optimize unbuffered reads */
    if (fp->_flags & __SNBF && fp->_ur == 0)
    {
        /* the following comes mainly from __srefill(), with slight
         * modifications
         */

        /* make sure stdio is set up */
        if (!__sdidinit)
            __sinit();

        fp->_r = 0;     /* largely a convenience for callers */

        /* SysV does not make this test; take it out for compatibility */
        if (fp->_flags & __SEOF)
            return (EOF);

        /* if not already reading, have to be reading and writing */
        if ((fp->_flags & __SRD) == 0) {
            if ((fp->_flags & __SRW) == 0) {
                errno = EBADF;
                fp->_flags |= __SERR;
                return (EOF);
            }
            /* switch to reading */
            if (fp->_flags & __SWR) {
                if (__sflush(fp))
                    return (EOF);
                fp->_flags &= ~__SWR;
                fp->_w = 0;
                fp->_lbfsize = 0;
            }
            fp->_flags |= __SRD;
        } else {
            /*
             * We were reading.  If there is an ungetc buffer,
             * we must have been reading from that.  Drop it,
             * restoring the previous buffer (if any).  If there
             * is anything in that buffer, return.
             */
            if (HASUB(fp)) {
                FREEUB(fp);
            }
        }

        /*
         * Before reading from a line buffered or unbuffered file,
         * flush all line buffered output files, per the ANSI C
         * standard.
         */

        if (fp->_flags & (__SLBF|__SNBF))
            (void) _fwalk(lflush);

        while (resid > 0) {
            int   len = (*fp->_read)(fp->_cookie, p, resid );
            fp->_flags &= ~__SMOD;
            if (len <= 0) {
                if (len == 0)
                    fp->_flags |= __SEOF;
                else {
                    fp->_flags |= __SERR;
                }
                return ((total - resid) / size);
            }
            p     += len;
            resid -= len;
        }
        return (count);
    }
    else
#endif
    {
        while (resid > (size_t)(r = fp->_r)) {
            (void)memcpy((void *)p, (void *)fp->_p, (size_t)r);
            fp->_p += r;
            /* fp->_r = 0 ... done in __srefill */
            p += r;
            resid -= r;
            if (__srefill(fp)) {
                /* no more input: return partial result */
                return ((total - resid) / size);
            }
        }
    }

    (void)memcpy((void *)p, (void *)fp->_p, resid);
    fp->_r -= resid;
    fp->_p += resid;
    return (count);
}
