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
#ifndef _WCHAR_H_
#define _WCHAR_H_

#include <sys/cdefs.h>
#include <stdio.h>

/* wchar_t is required in stdlib.h according to POSIX */
#define __need___wchar_t
#include <stddef.h>

#include <stdarg.h>
#include <time.h>
#include <malloc.h>

#include <stddef.h>

/* IMPORTANT: Any code that relies on wide character support is essentially
 *            non-portable and/or broken. the only reason this header exist
 *            is because I'm really a nice guy. However, I'm not nice enough
 *            to provide you with a real implementation. instead wchar_t == char
 *            and all wc functions are stubs to their "normal" equivalent...
 */

__BEGIN_DECLS

typedef int                     wint_t;
typedef struct { int  dummy; }  mbstate_t;

typedef enum {
    WC_TYPE_INVALID = 0,
    WC_TYPE_ALNUM,
    WC_TYPE_ALPHA,
    WC_TYPE_BLANK,
    WC_TYPE_CNTRL,
    WC_TYPE_DIGIT,
    WC_TYPE_GRAPH,
    WC_TYPE_LOWER,
    WC_TYPE_PRINT,
    WC_TYPE_PUNCT,
    WC_TYPE_SPACE,
    WC_TYPE_UPPER,
    WC_TYPE_XDIGIT,
    WC_TYPE_MAX
} wctype_t;

#define  WCHAR_MAX   255
#define  WCHAR_MIN   0
#define  WEOF        (-1)

extern wint_t            btowc(int);
extern int               fwprintf(FILE *, const wchar_t *, ...);
extern int               fwscanf(FILE *, const wchar_t *, ...);
extern int               iswalnum(wint_t);
extern int               iswalpha(wint_t);
extern int               iswcntrl(wint_t);
extern int               iswdigit(wint_t);
extern int               iswgraph(wint_t);
extern int               iswlower(wint_t);
extern int               iswprint(wint_t);
extern int               iswpunct(wint_t);
extern int               iswspace(wint_t);
extern int               iswupper(wint_t);
extern int               iswxdigit(wint_t);
extern int               iswctype(wint_t, wctype_t);
extern wint_t            fgetwc(FILE *);
extern wchar_t          *fgetws(wchar_t *, int, FILE *);
extern wint_t            fputwc(wchar_t, FILE *);
extern int               fputws(const wchar_t *, FILE *);
extern int               fwide(FILE *, int);
extern wint_t            getwc(FILE *);
extern wint_t            getwchar(void);
extern int               mbsinit(const mbstate_t *);
extern size_t            mbrlen(const char *, size_t, mbstate_t *);
extern size_t            mbrtowc(wchar_t *, const char *, size_t, mbstate_t *);
extern size_t            mbsrtowcs(wchar_t *, const char **, size_t, mbstate_t *);
extern size_t            mbstowcs(wchar_t *, const char *, size_t);
extern wint_t            putwc(wchar_t, FILE *);
extern wint_t            putwchar(wchar_t);
extern int               swprintf(wchar_t *, size_t, const wchar_t *, ...);
extern int               swscanf(const wchar_t *, const wchar_t *, ...);
extern wint_t            towlower(wint_t);
extern wint_t            towupper(wint_t);
extern wint_t            ungetwc(wint_t, FILE *);
extern int               vfwprintf(FILE *, const wchar_t *, va_list);
extern int               vwprintf(const wchar_t *, va_list);
extern int               vswprintf(wchar_t *, size_t, const wchar_t *, va_list);
extern size_t            wcrtomb(char *, wchar_t, mbstate_t *);
extern wchar_t          *wcscat(wchar_t *, const wchar_t *);
extern wchar_t          *wcschr(const wchar_t *, wchar_t);
extern int               wcscmp(const wchar_t *, const wchar_t *);
extern int               wcscoll(const wchar_t *, const wchar_t *);
extern wchar_t          *wcscpy(wchar_t *, const wchar_t *);
extern size_t            wcscspn(const wchar_t *, const wchar_t *);
extern size_t            wcsftime(wchar_t *, size_t, const wchar_t *, const struct tm *);
extern size_t            wcslen(const wchar_t *);
extern wchar_t          *wcsncat(wchar_t *, const wchar_t *, size_t);
extern int               wcsncmp(const wchar_t *, const wchar_t *, size_t);
extern wchar_t          *wcsncpy(wchar_t *, const wchar_t *, size_t);
extern wchar_t          *wcspbrk(const wchar_t *, const wchar_t *);
extern wchar_t          *wcsrchr(const wchar_t *, wchar_t);
extern size_t            wcsrtombs(char *, const wchar_t **, size_t, mbstate_t *);
extern size_t            wcsspn(const wchar_t *, const wchar_t *);
extern wchar_t          *wcsstr(const wchar_t *, const wchar_t *);
extern double            wcstod(const wchar_t *, wchar_t **);
extern wchar_t          *wcstok(wchar_t *, const wchar_t *, wchar_t **);
extern long int          wcstol(const wchar_t *, wchar_t **, int);
extern size_t            wcstombs(char *, const wchar_t *, size_t);
extern unsigned long int wcstoul(const wchar_t *, wchar_t **, int);
extern wchar_t          *wcswcs(const wchar_t *, const wchar_t *);
extern int               wcswidth(const wchar_t *, size_t);
extern size_t            wcsxfrm(wchar_t *, const wchar_t *, size_t);
extern int               wctob(wint_t);
extern wctype_t          wctype(const char *);
extern int               wcwidth(wchar_t);
extern wchar_t          *wmemchr(const wchar_t *, wchar_t, size_t);
extern int               wmemcmp(const wchar_t *, const wchar_t *, size_t);
extern wchar_t          *wmemcpy(wchar_t *, const wchar_t *, size_t);
extern wchar_t          *wmemmove(wchar_t *, const wchar_t *, size_t);
extern wchar_t          *wmemset(wchar_t *, wchar_t, size_t);
extern int               wprintf(const wchar_t *, ...);
extern int               wscanf(const wchar_t *, ...);

/* No really supported.  These are just for making libstdc++-v3 happy.  */
typedef void *wctrans_t;
extern wint_t		 towctrans(wint_t, wctrans_t);
extern wctrans_t	 wctrans (const char *);

__END_DECLS

#endif /* _WCHAR_H_ */
