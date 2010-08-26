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
#include <sys/types.h>

#ifndef _STDLIB_H_
#define _STDLIB_H_

#include <sys/cdefs.h>

/* wchar_t is required in stdlib.h according to POSIX.
 * note that defining __need_wchar_t prevents stddef.h
 * to define all other symbols it does normally */
#define __need_wchar_t
#include <stddef.h>

#include <stddef.h>
#include <string.h>
#include <alloca.h>
#include <strings.h>
#include <memory.h>

__BEGIN_DECLS

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

extern __noreturn void exit(int);
extern __noreturn void abort(void);
extern int atexit(void (*)(void));
extern int on_exit(void (*)(int, void *), void *);

extern char *getenv(const char *);
extern int putenv(const char *);
extern int setenv(const char *, const char *, int);
extern int unsetenv(const char *);
extern int clearenv(void);

extern char *mktemp (char *);
extern int mkstemp (char *);

extern long strtol(const char *, char **, int);
extern long long strtoll(const char *, char **, int);
extern unsigned long strtoul(const char *, char **, int);
extern unsigned long long strtoull(const char *, char **, int);
extern double strtod(const char *nptr, char **endptr);

static __inline__ float strtof(const char *nptr, char **endptr)
{
    return (float)strtod(nptr, endptr);
}

extern int atoi(const char *);
extern long atol(const char *);
extern long long atoll(const char *);

static __inline__ double atof(const char *nptr)
{
    return (strtod(nptr, NULL));
}

static __inline__ int abs(int __n) {
    return (__n < 0) ? -__n : __n;
}

static __inline__ long labs(long __n) {
    return (__n < 0L) ? -__n : __n;
}

static __inline__ long long llabs(long long __n) {
    return (__n < 0LL) ? -__n : __n;
}

extern char * realpath(const char *path, char *resolved);
extern int system(const char * string);

extern void * bsearch(const void *key, const void *base0,
	size_t nmemb, size_t size,
	int (*compar)(const void *, const void *));

extern void qsort(void *, size_t, size_t, int (*)(const void *, const void *));

extern unsigned int arc4random(void);
extern void arc4random_stir(void);
extern void arc4random_addrandom(unsigned char *, int);

#define RAND_MAX 0x7fffffff
extern int rand(void);
extern void srand(unsigned int __s);
extern long random(void);
extern void srandom(unsigned int __s);

/* Basic PTY functions.  These only work if devpts is mounted! */

extern int    unlockpt(int);
extern char*  ptsname(int);
extern int    ptsname_r(int, char*, size_t);
extern int    getpt(void);

static __inline__ int grantpt(int __fd)
{
  (void)__fd;
  return 0;     /* devpts does this all for us! */
}

typedef struct {
    int  quot;
    int  rem;
} div_t;

extern div_t   div(int, int);

typedef struct {
    long int  quot;
    long int  rem;
} ldiv_t;

extern ldiv_t   ldiv(long, long);

typedef struct {
    long long int  quot;
    long long int  rem;
} lldiv_t;

extern lldiv_t   lldiv(long long, long long);

/* make STLPort happy */
extern int      mblen(const char *, size_t);
extern size_t   mbstowcs(wchar_t *, const char *, size_t);
extern int      mbtowc(wchar_t *, const char *, size_t);

/* Likewise, make libstdc++-v3 happy.  */
extern int	wctomb(char *, wchar_t);
extern size_t	wcstombs(char *, const wchar_t *, size_t);
#define MB_CUR_MAX 1

__END_DECLS

#endif /* _STDLIB_H_ */
