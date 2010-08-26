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
#include <wchar.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

/* stubs for wide-char functions */
wint_t  btowc(int c)
{
  return (c == EOF) ? WEOF : c;
}

int fwprintf(FILE *stream, const wchar_t *format, ...)
{
    va_list  args;
    int      result;

    va_start(args, format);
    result = vfwprintf(stream, format, args);
    va_end(args);
    return result;
}

int wprintf(const wchar_t *format, ...)
{
    va_list  args;
    int      result;

    va_start(args, format);
    result = vwprintf(format, args);
    va_end(args);
    return result;
}

int swprintf(wchar_t *s, size_t n, const wchar_t *format, ...)
{
    va_list  args;
    int      result;

    va_start(args, format);
    result = vswprintf(s, n, format, args);
    va_end(args);
    return result;
}

int vwprintf(const wchar_t *format, va_list arg)
{
    return vprintf((const char*)format, arg);
}

int vfwprintf(FILE *stream, const wchar_t *format, va_list arg)
{
    return vfprintf(stream, (const char*)format, arg);
}

int vswprintf(wchar_t *s, size_t n, const wchar_t *format, va_list arg)
{
    return vsnprintf( (char*)s, n, (const char*)format, arg );
}

int fwscanf(FILE *stream, const wchar_t *format, ... )
{
    va_list  args;
    int      result;

    va_start (args, format);
    result = vfscanf( stream, (const char*)format, args );
    va_end (args);
    return result;
}

int wscanf(const wchar_t *format, ... )
{
    va_list  args;
    int      result;

    va_start (args, format);
    result = vscanf( (const char*)format, args );
    va_end (args);
    return result;
}

int swscanf(const wchar_t *s, const wchar_t *format, ... )
{
    va_list  args;
    int      result;

    va_start (args, format);
    result = vscanf( (const char*)format, args );
    va_end (args);
    return result;
}

int iswalnum(wint_t wc) { return isalnum(wc); }
int iswalpha(wint_t wc) { return isalpha(wc); }
int iswcntrl(wint_t wc) { return iscntrl(wc); }
int iswdigit(wint_t wc) { return isdigit(wc); }
int iswgraph(wint_t wc) { return isgraph(wc); }
int iswlower(wint_t wc) { return islower(wc); }
int iswprint(wint_t wc) { return isprint(wc); }
int iswpunct(wint_t wc) { return ispunct(wc); }
int iswspace(wint_t wc) { return isspace(wc); }
int iswupper(wint_t wc) { return isupper(wc); }
int iswxdigit(wint_t wc) { return isxdigit(wc); }

int iswctype(wint_t wc, wctype_t charclass)
{
    switch (charclass) {
        case WC_TYPE_ALNUM: return isalnum(wc);
        case WC_TYPE_ALPHA: return isalpha(wc);
        case WC_TYPE_BLANK: return isblank(wc);
        case WC_TYPE_CNTRL: return iscntrl(wc);
        case WC_TYPE_DIGIT: return isdigit(wc);
        case WC_TYPE_GRAPH: return isgraph(wc);
        case WC_TYPE_LOWER: return islower(wc);
        case WC_TYPE_PRINT: return isprint(wc);
        case WC_TYPE_PUNCT: return ispunct(wc);
        case WC_TYPE_SPACE: return isspace(wc);
        case WC_TYPE_UPPER: return isupper(wc);
        case WC_TYPE_XDIGIT: return isxdigit(wc);
        default: return 0;
    };
}

wint_t fgetwc(FILE *stream)
{
    return fgetc(stream);
}

wchar_t *fgetws(wchar_t *ws, int n, FILE *stream)
{
    return (wchar_t*) fgets((char*)ws, n, stream);
}

wint_t   fputwc(wchar_t wc, FILE *stream)
{
    return (wint_t)fputc((char)wc, stream);
}

int  fputws(const wchar_t *str, FILE *stream)
{
    return fputs( (const char*)str, stream );
}

int  fwide(FILE *stream, int  mode)
{
    stream=stream;
    return (mode);
}

wint_t  getwc(FILE *stream)
{
    return getc(stream);
}

wint_t  getwchar(void)
{
    return getchar();
}

int mbsinit(const mbstate_t *ps)
{
    ps=ps;
    return 1;
}

size_t mbrlen(const char *s, size_t n, mbstate_t *ps)
{
    return (n != 0);
}

size_t mbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *ps)
{
    if (s == NULL) {
        s   = "";
        pwc = NULL;
    }
    if (n == 0) {
        if (pwc)
            *pwc = 0;
        return 0;
    }
    if (pwc)
        *pwc = *s;

    return (*s != 0);
}

size_t mbsrtowcs(wchar_t *dst, const char **src, size_t len, mbstate_t *ps)
{
    const char*  s  = *src;
    const char*  s2 = memchr( s, 0, len );

    if (s2 != NULL)
        len = (size_t)(s2 - s) + 1U;

    if (dst)
        memcpy( (char*)dst, s, len );

    *src = s + len;
    return len;
}

size_t mbstowcs(wchar_t *dst, const char *src, size_t len)
{
    return mbsrtowcs(dst, &src, len, NULL);
}

wint_t  putwc(wchar_t wc, FILE *stream)
{
    return fputc((char)wc, stream);
}

wint_t  putwchar(wchar_t wc)
{
    return  putchar((char)wc);
}

wint_t  towlower(wint_t wc)
{
    return tolower(wc);
}

wint_t  towupper(wint_t  wc)
{
    return toupper(wc);
}

wint_t  ungetwc(wint_t wc, FILE *stream)
{
    return ungetc((char)wc, stream);
}

size_t wcrtomb(char *s, wchar_t wc, mbstate_t *ps)
{
    if (s != NULL)
        *s = 1;
    return 1;
}

wchar_t *wcscat(wchar_t *ws1, const wchar_t *ws2)
{
    return (wchar_t*) strcat((char*)ws1, (const char*)ws2);
}

wchar_t *wcschr(const wchar_t *ws, wchar_t wc)
{
    return (wchar_t*)strchr( (const char*)ws, (char)wc );
}

int wcscmp(const wchar_t *ws1, const wchar_t *ws2)
{
    return strcmp( (const char*)ws1, (const char*)ws2 );
}

int wcscoll(const wchar_t *ws1, const wchar_t *ws2)
{
    return strcmp( (const char*)ws1, (const char*)ws2 );
}

wchar_t *wcscpy(wchar_t *ws1, const wchar_t *ws2)
{
    return (wchar_t*) strcpy( (char*)ws1, (const char*)ws2 );
}

size_t wcscspn(const wchar_t *ws1, const wchar_t *ws2)
{
    return strspn( (const char*)ws1, (const char*)ws2 );
}

size_t wcslen(const wchar_t *ws)
{
    return (size_t)strlen( (const char*)ws );
}

size_t wcsftime(wchar_t *wcs, size_t maxsize, const wchar_t *format,  const struct tm *timptr)
{
    return strftime( (char*)wcs, maxsize, (const char*)format, timptr );
}

wchar_t *wcsncat(wchar_t *ws1, const wchar_t *ws2, size_t n)
{
    return (wchar_t*) strncat( (char*)ws1, (const char*)ws2, n );
}

int wcsncmp(const wchar_t *ws1, const wchar_t *ws2, size_t n)
{
    return strncmp( (const char*)ws1, (const char*)ws2, n );
}

wchar_t *wcsncpy(wchar_t *ws1, const wchar_t *ws2, size_t n)
{
    return (wchar_t*) strncpy( (char*)ws1, (const char*)ws2, n );
}

wchar_t *wcspbrk(const wchar_t *ws1, const wchar_t *ws2)
{
    return (wchar_t*) strpbrk( (const char*)ws1, (const char*)ws2 );
}

wchar_t *wcsrchr(const wchar_t *ws, wchar_t wc)
{
    return (wchar_t*) strrchr( (const char*)ws, (int)wc );
}

size_t wcsrtombs(char *dst, const wchar_t **src, size_t len, mbstate_t *ps)
{
    const char*  s = (const char*)*src;
    const char*  s2 = memchr( s, 0, len );

    if (s2 != NULL)
        len = (s2 - s)+1;

    if (dst != NULL)
        memcpy( dst, s, len );

    *src = (wchar_t*)(s + len);
    return len;
}

size_t wcstombs(char *dst, const wchar_t *src, size_t len)
{
    return wcsrtombs(dst, &src, len, NULL);
}

size_t wcsspn(const wchar_t *ws1, const wchar_t *ws2)
{
    return strspn( (const char*)ws1, (const char*)ws2 );
}

wchar_t *wcsstr(const wchar_t *ws1, const wchar_t *ws2)
{
    return (wchar_t*) strstr( (const char*)ws1, (const char*)ws2 );
}

double wcstod(const wchar_t *nptr, wchar_t **endptr)
{
    return strtod( (const char*)nptr, (char**)endptr );
}

wchar_t *wcstok(wchar_t *ws1, const wchar_t *ws2, wchar_t **ptr)
{
    return (wchar_t*) strtok_r( (char*)ws1, (const char*)ws2, (char**)ptr );
}

long int wcstol(const wchar_t *nptr, wchar_t **endptr, int base)
{
    return strtol( (const char*)nptr, (char**)endptr, base );
}

unsigned long int wcstoul(const wchar_t *nptr, wchar_t **endptr, int base)
{
    return strtoul( (const char*)nptr, (char**)endptr, base );
}

wchar_t *wcswcs(const wchar_t *ws1, const wchar_t *ws2)
{
    return (wchar_t*) strstr( (const char*)ws1, (const char*)ws2 );
}

int wcswidth(const wchar_t *pwcs, size_t n)
{
    return  strnlen( (const char*)pwcs, n );
}

size_t wcsxfrm(wchar_t *ws1, const wchar_t *ws2, size_t n)
{
    memcpy( (char*)ws1, (const char*)ws2, n );
    return n;
}

int wctob(wint_t c)
{
    return c;
}

wctype_t wctype(const char *property)
{
    static const char* const  properties[WC_TYPE_MAX] =
    {
        "<invalid>",
        "alnum", "alpha", "blank", "cntrl", "digit", "graph",
        "lower", "print", "punct", "space", "upper", "xdigit"
    };
    int  nn;

    for ( nn = 0; nn < WC_TYPE_MAX; nn++ )
        if ( !strcmp( properties[nn], property ) )
            return (wctype_t)(nn);

    return 0;
}

int wcwidth(wchar_t wc)
{
    return (wc > 0);
}

wchar_t *wmemchr(const wchar_t *ws, wchar_t wc, size_t n)
{
    return (wchar_t*)  memchr( (const char*)ws, (int)wc, n );
}

int wmemcmp(const wchar_t *ws1, const wchar_t *ws2, size_t n)
{
    return  memcmp( (const char*)ws1, (const char*)ws2, n );
}

wchar_t *wmemcpy(wchar_t *ws1, const wchar_t *ws2, size_t n)
{
    return (wchar_t*) memcpy( (char*)ws1, (const char*)ws2, n );
}

wchar_t *wmemmove(wchar_t *ws1, const wchar_t *ws2, size_t n)
{
    return (wchar_t*)memmove( (char*)ws1, (const char*)ws2, n );
}

wchar_t *wmemset(wchar_t *ws, wchar_t wc, size_t n)
{
    return (wchar_t*) memset( (char*)ws, (int)wc, n );
}
