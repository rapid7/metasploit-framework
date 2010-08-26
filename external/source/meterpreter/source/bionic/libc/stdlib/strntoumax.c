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
#include <stddef.h>
#include <stdint.h>
#include <ctype.h>

static inline int digitval(int ch)
{
    unsigned  d;

    d = (unsigned)(ch - '0');
    if (d < 10) return (int)d;

    d = (unsigned)(ch - 'a');
    if (d < 6) return (int)(d+10);

    d = (unsigned)(ch - 'A');
    if (d < 6) return (int)(d+10);

    return -1;
}

uintmax_t
strntoumax(const char *nptr, char **endptr, int base, size_t n)
{
    const unsigned char*  p   = nptr;
    const unsigned char*  end = p + n;
    int                   minus = 0;
    uintmax_t             v = 0;
    int                   d;

    /* skip leading space */
    while (p < end && isspace(*p))
        p++;

    /* Single optional + or - */
    if (p < end) {
        char c = p[0];
        if ( c == '-' || c == '+' ) {
            minus = (c == '-');
            p++;
        }
    }

    if ( base == 0 ) {
        if ( p+2 < end && p[0] == '0' && (p[1] == 'x' || p[1] == 'X') ) {
            p += 2;
            base = 16;
        } else if ( p+1 < end && p[0] == '0' ) {
            p   += 1;
            base = 8;
        } else {
            base = 10;
        }
    } else if ( base == 16 ) {
        if ( p+2 < end && p[0] == '0' && (p[1] == 'x' || p[1] == 'X') ) {
            p += 2;
        }
    }

    while ( p < end && (d = digitval(*p)) >= 0 && d < base ) {
        v = v*base + d;
        p += 1;
    }

    if ( endptr )
        *endptr = (char *)p;

    return minus ? -v : v;
}
