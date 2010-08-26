/*

Copyright (c) 2007-2008  Michael G Schwern

This software originally derived from Paul Sheer's pivotal_gmtime_r.c.

The MIT License:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Origin: http://code.google.com/p/y2038
Modified for Bionic by the Android Open Source Project

*/
#ifndef TIME64_H
#define TIME64_H

#include <sys/cdefs.h>
#include <time.h>
#include <stdint.h>

__BEGIN_DECLS

typedef int64_t  time64_t;

struct tm *gmtime64_r (const time64_t *, struct tm *);
struct tm *localtime64_r (const time64_t *, struct tm *);
struct tm *gmtime64 (const time64_t *);
struct tm *localtime64 (const time64_t *);

char *asctime64 (const struct tm *);
char *asctime64_r (const struct tm *, char *);

char *ctime64 (const time64_t*);
char *ctime64_r (const time64_t*, char*);

time64_t timegm64 (const struct tm *);
time64_t mktime64 (const struct tm *);
time64_t timelocal64 (const struct tm *);

__END_DECLS

#endif /* TIME64_H */
