/*      $OpenBSD: arc4random.c,v 1.19 2008/06/04 00:50:23 djm Exp $        */

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Arc4 random number generator for OpenBSD.
 *
 * This code is derived from section 17.1 of Applied Cryptography,
 * second edition, which describes a stream cipher allegedly
 * compatible with RSA Labs "RC4" cipher (the actual description of
 * which is a trade secret).  The same algorithm is used as a stream
 * cipher called "arcfour" in Tatu Ylonen's ssh package.
 *
 * Here the stream cipher has been modified always to include the time
 * when initializing the state.  That makes it impossible to
 * regenerate the same random sequence twice, so this can't be used
 * for encryption, but will generate good random numbers.
 *
 * RC4 is a registered trademark of RSA Laboratories.
 */

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include "thread_private.h"

/* BIONIC-BEGIN */
/* this lock should protect the global variables in this file */
static pthread_mutex_t  _arc4_lock = PTHREAD_MUTEX_INITIALIZER;
#define  _ARC4_LOCK()      pthread_mutex_lock(&_arc4_lock)
#define  _ARC4_UNLOCK()    pthread_mutex_unlock(&_arc4_lock)
/* BIONIC-END */

#ifdef __GNUC__
#define inline __inline
#else                           /* !__GNUC__ */
#define inline
#endif                          /* !__GNUC__ */

struct arc4_stream {
        u_int8_t i;
        u_int8_t j;
        u_int8_t s[256];
};

static int rs_initialized;
static struct arc4_stream rs;
static pid_t arc4_stir_pid;
static int arc4_count;

static inline u_int8_t arc4_getbyte(void);

static inline void
arc4_init(void)
{
        int     n;

        for (n = 0; n < 256; n++)
                rs.s[n] = n;
        rs.i = 0;
        rs.j = 0;
}

static inline void
arc4_addrandom(u_char *dat, int datlen)
{
        int     n;
        u_int8_t si;

        rs.i--;
        for (n = 0; n < 256; n++) {
                rs.i = (rs.i + 1);
                si = rs.s[rs.i];
                rs.j = (rs.j + si + dat[n % datlen]);
                rs.s[rs.i] = rs.s[rs.j];
                rs.s[rs.j] = si;
        }
        rs.j = rs.i;
}

static void
arc4_stir(void)
{
#if 1  /* BIONIC-BEGIN */
	int     i, fd;
	union {
		struct timeval tv;
		u_int rnd[128 / sizeof(u_int)];
	}       rdat;
	int	n;

        if (!rs_initialized) {
                arc4_init();
                rs_initialized = 1;
        }

	fd = open("/dev/urandom", O_RDONLY);
	if (fd != -1) {
		read(fd, rdat.rnd, sizeof(rdat.rnd));
		close(fd);
	}
        else
        {
	    /* fd < 0 ?  Ah, what the heck. We'll just take
	     * whatever was on the stack. just add a little more
             * time-based randomness though
             */
            gettimeofday(&rdat.tv, NULL);
        }

        arc4_stir_pid = getpid();
	arc4_addrandom((void *) &rdat, sizeof(rdat));
#else  /* BIONIC-END */
        int     i, mib[2];
        size_t        len;
        u_char rnd[128];

        if (!rs_initialized) {
                arc4_init();
                rs_initialized = 1;
        }

        mib[0] = CTL_KERN;
        mib[1] = KERN_ARND;

        len = sizeof(rnd);
        sysctl(mib, 2, rnd, &len, NULL, 0);

        arc4_stir_pid = getpid();
        arc4_addrandom(rnd, sizeof(rnd));
#endif
        /*
         * Discard early keystream, as per recommendations in:
         * http://www.wisdom.weizmann.ac.il/~itsik/RC4/Papers/Rc4_ksa.ps
         */
        for (i = 0; i < 256; i++)
                (void)arc4_getbyte();
        arc4_count = 1600000;
}

static inline u_int8_t
arc4_getbyte(void)
{
        u_int8_t si, sj;

        rs.i = (rs.i + 1);
        si = rs.s[rs.i];
        rs.j = (rs.j + si);
        sj = rs.s[rs.j];
        rs.s[rs.i] = sj;
        rs.s[rs.j] = si;
        return (rs.s[(si + sj) & 0xff]);
}

u_int8_t
__arc4_getbyte(void)
{
        u_int8_t val;

        _ARC4_LOCK();
        if (--arc4_count == 0 || !rs_initialized)
                arc4_stir();
        val = arc4_getbyte();
        _ARC4_UNLOCK();
        return val;
}

static inline u_int32_t
arc4_getword(void)
{
        u_int32_t val;
        val = arc4_getbyte() << 24;
        val |= arc4_getbyte() << 16;
        val |= arc4_getbyte() << 8;
        val |= arc4_getbyte();
        return val;
}

void
arc4random_stir(void)
{
        _ARC4_LOCK();
        arc4_stir();
        _ARC4_UNLOCK();
}

void
arc4random_addrandom(u_char *dat, int datlen)
{
        _ARC4_LOCK();
        if (!rs_initialized)
                arc4_stir();
        arc4_addrandom(dat, datlen);
        _ARC4_UNLOCK();
}

u_int32_t
arc4random(void)
{
        u_int32_t val;
        _ARC4_LOCK();
        arc4_count -= 4;
        if (arc4_count <= 0 || !rs_initialized || arc4_stir_pid != getpid())
                arc4_stir();
        val = arc4_getword();
        _ARC4_UNLOCK();
        return val;
}

void
arc4random_buf(void *_buf, size_t n)
{
        u_char *buf = (u_char *)_buf;
        _ARC4_LOCK();
        if (!rs_initialized || arc4_stir_pid != getpid())
                arc4_stir();
        while (n--) {
                if (--arc4_count <= 0)
                        arc4_stir();
                buf[n] = arc4_getbyte();
        }
        _ARC4_UNLOCK();
}

/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
u_int32_t
arc4random_uniform(u_int32_t upper_bound)
{
        u_int32_t r, min;

        if (upper_bound < 2)
                return 0;

#if (ULONG_MAX > 0xffffffffUL)
        min = 0x100000000UL % upper_bound;
#else
        /* Calculate (2**32 % upper_bound) avoiding 64-bit math */
        if (upper_bound > 0x80000000)
                min = 1 + ~upper_bound;                /* 2**32 - upper_bound */
        else {
                /* (2**32 - (x * 2)) % x == 2**32 % x when x <= 2**31 */
                min = ((0xffffffff - (upper_bound * 2)) + 1) % upper_bound;
        }
#endif

        /*
         * This could theoretically loop forever but each retry has
         * p > 0.5 (worst case, usually far better) of selecting a
         * number inside the range we need, so it should rarely need
         * to re-roll.
         */
        for (;;) {
                r = arc4random();
                if (r >= min)
                        break;
        }

        return r % upper_bound;
}

#if 0
/*-------- Test code for i386 --------*/
#include <stdio.h>
#include <machine/pctr.h>
int
main(int argc, char **argv)
{
        const int iter = 1000000;
        int     i;
        pctrval v;

        v = rdtsc();
        for (i = 0; i < iter; i++)
                arc4random();
        v = rdtsc() - v;
        v /= iter;

        printf("%qd cycles\n", v);
}
#endif
