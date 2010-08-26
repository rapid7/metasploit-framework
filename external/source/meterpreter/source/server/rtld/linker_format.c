/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include "linker_format.h"
#include "linker_debug.h"

#include "msflinker.h"

/* define UNIT_TESTS to build this file as a single executable that runs
 * the formatter's unit tests
 */
#define xxUNIT_TESTS

/*** Generic output sink
 ***/

typedef struct {
    void *opaque;
    void (*send)(void *opaque, const char *data, int len);
} Out;

static void
out_send(Out *o, const void *data, size_t len)
{
    o->send(o->opaque, data, (int)len);
}

static void
out_send_repeat(Out *o, char ch, int count)
{
    char pad[8];
    const int padSize = (int)sizeof(pad);

    memset(pad, ch, sizeof(pad));
    while (count > 0) {
        int avail = count;
        if (avail > padSize) {
            avail = padSize;
        }
        o->send(o->opaque, pad, avail);
        count -= avail;
    }
}

/* forward declaration */
static void
out_vformat(Out *o, const char *format, va_list args);

/*** Bounded buffer output
 ***/

typedef struct {
    Out out[1];
    char *buffer;
    char *pos;
    char *end;
    int total;
} BufOut;

static void
buf_out_send(void *opaque, const char *data, int len)
{
    BufOut *bo = opaque;

    if (len < 0)
        len = strlen(data);

    bo->total += len;

    while (len > 0) {
        int avail = bo->end - bo->pos;
        if (avail == 0)
            break;
        if (avail > len)
            avail = len;
        memcpy(bo->pos, data, avail);
        bo->pos += avail;
        bo->pos[0] = '\0';
        len -= avail;
    }
}

static Out*
buf_out_init(BufOut *bo, char *buffer, size_t size)
{
    if (size == 0)
        return NULL;

    bo->out->opaque = bo;
    bo->out->send   = buf_out_send;
    bo->buffer      = buffer;
    bo->end         = buffer + size - 1;
    bo->pos         = bo->buffer;
    bo->pos[0]      = '\0';
    bo->total       = 0;

    return bo->out;
}

static int
buf_out_length(BufOut *bo)
{
    return bo->total;
}

static int
vformat_buffer(char *buff, size_t buffsize, const char *format, va_list args)
{
    BufOut bo;
    Out *out;

    out = buf_out_init(&bo, buff, buffsize);
    if (out == NULL)
        return 0;

    out_vformat(out, format, args);

    return buf_out_length(&bo);
}

int
format_buffer(char *buff, size_t buffsize, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = vformat_buffer(buff, buffsize, format, args);
    va_end(args);

    return ret;
}

/* The __stack_chk_fail() function calls __libc_android_log_print()
 * which calls vsnprintf().
 *
 * We define our version of the function here to avoid dragging
 * about 25 KB of C library routines related to formatting.
 */
int
vsnprintf(char *buff, size_t bufsize, const char *format, va_list args)
{
    return format_buffer(buff, bufsize, format, args);
}

#if LINKER_DEBUG

#if !LINKER_DEBUG_TO_LOG

/*** File descriptor output
 ***/

typedef struct {
    Out out[1];
    int fd;
    int total;
} FdOut;

static void
fd_out_send(void *opaque, const char *data, int len)
{
    FdOut *fdo = opaque;

    if (len < 0)
        len = strlen(data);

    while (len > 0) {
        int ret = write(fdo->fd, data, len);
        if (ret < 0) {
            if (ret == -EINTR)
                continue;
            break;
        }
        data += ret;
        len -= ret;
        fdo->total += ret;
    }
}

static Out*
fd_out_init(FdOut *fdo, int  fd)
{
    fdo->out->opaque = fdo;
    fdo->out->send = fd_out_send;
    fdo->fd = fd;
    fdo->total = 0;

    return fdo->out;
}

static int
fd_out_length(FdOut *fdo)
{
    return fdo->total;
}


int
format_fd(int fd, const char *format, ...)
{
    FdOut fdo;
    Out* out;
    va_list args;

    out = fd_out_init(&fdo, fd);
    if (out == NULL)
        return 0;

    va_start(args, format);
    out_vformat(out, format, args);
    va_end(args);

    return fd_out_length(&fdo);
}

#else /* LINKER_DEBUG_TO_LOG */

/*** Log output
 ***/

/* We need our own version of __libc_android_log_vprint, otherwise
 * the log output is completely broken. Probably due to the fact
 * that the C library is not initialized yet.
 *
 * You can test that by setting CUSTOM_LOG_VPRINT to 0
 */
#define  CUSTOM_LOG_VPRINT  1

#if CUSTOM_LOG_VPRINT

#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>

static int log_vprint(int prio, const char *tag, const char *fmt, va_list  args)
{
    char buf[1024];
    int result;
    static int log_fd = -1;

    result = vformat_buffer(buf, sizeof buf, fmt, args);

    if (log_fd < 0) {
        // log_fd = open("/dev/log/main", O_WRONLY);
        log_fd = 2;
        //if (log_fd < 0)
        //    return result;
    }

    {
        ssize_t ret;
        struct iovec vec[3];

        vec[0].iov_base = (unsigned char *) &prio;
        vec[0].iov_len = 1;
        vec[1].iov_base = (void *) tag;
        vec[1].iov_len = strlen(tag) + 1;
        vec[2].iov_base = (void *) buf;
        vec[2].iov_len = strlen(buf) + 1;

        do {
            ret = writev(log_fd, vec, 3);
        } while ((ret < 0) && (ret == -EINTR));
    }
    return result;
}

#define  __libc_android_log_vprint  log_vprint

#else /* !CUSTOM_LOG_VPRINT */

extern int __libc_android_log_vprint(int  prio, const char* tag, const char*  format, va_list ap);

#endif /* !CUSTOM_LOG_VPRINT */

int
format_log(int prio, const char *tag, const char *format, ...)
{
    int ret;
    va_list  args;
    va_start(args, format);
    ret = __libc_android_log_vprint(prio, tag, format, args);
    va_end(args);
    return ret;
}

#endif /* LINKER_DEBUG_TO_LOG */

#endif /* LINKER_DEBUG */

/*** formatted output implementation
 ***/

/* Parse a decimal string from 'format + *ppos',
 * return the value, and writes the new position past
 * the decimal string in '*ppos' on exit.
 *
 * NOTE: Does *not* handle a sign prefix.
 */
static unsigned
parse_decimal(const char *format, int *ppos)
{
    const char* p = format + *ppos;
    unsigned result = 0;

    for (;;) {
        int ch = *p;
        unsigned d = (unsigned)(ch - '0');

        if (d >= 10U)
            break;

        result = result*10 + d;
        p++;
    }
    *ppos = p - format;
    return result;
}

/* write an octal/decimal/number into a bounded buffer.
 * assumes that bufsize > 0, and 'digits' is a string of
 * digits of at least 'base' values.
 */
static void
format_number(char *buffer, size_t bufsize, uint64_t value, int base, const char *digits)
{
    char *pos = buffer;
    char *end = buffer + bufsize - 1;

    /* generate digit string in reverse order */
    while (value) {
        unsigned d = value % base;
        value /= base;
        if (pos < end) {
            *pos++ = digits[d];
        }
    }

    /* special case for 0 */
    if (pos == buffer) {
        if (pos < end) {
            *pos++ = '0';
        }
    }
    pos[0] = '\0';

    /* now reverse digit string in-place */
    end = pos - 1;
    pos = buffer;
    while (pos < end) {
        int ch = pos[0];
        pos[0] = end[0];
        end[0] = (char) ch;
        pos++;
        end--;
    }
}

/* Write an integer (octal or decimal) into a buffer, assumes buffsize > 2 */
static void
format_integer(char *buffer, size_t buffsize, uint64_t value, int base, int isSigned)
{
    if (isSigned && (int64_t)value < 0) {
        buffer[0] = '-';
        buffer += 1;
        buffsize -= 1;
        value = (uint64_t)(-(int64_t)value);
    }

    format_number(buffer, buffsize, value, base, "0123456789");
}

/* Write an octal into a buffer, assumes buffsize > 2 */
static void
format_octal(char *buffer, size_t buffsize, uint64_t value, int isSigned)
{
    format_integer(buffer, buffsize, value, 8, isSigned);
}

/* Write a decimal into a buffer, assumes buffsize > 2 */
static void
format_decimal(char *buffer, size_t buffsize, uint64_t value, int isSigned)
{
    format_integer(buffer, buffsize, value, 10, isSigned);
}

/* Write an hexadecimal into a buffer, isCap is true for capital alphas.
 * Assumes bufsize > 2 */
static void
format_hex(char *buffer, size_t buffsize, uint64_t value, int isCap)
{
    const char *digits = isCap ? "0123456789ABCDEF" : "0123456789abcdef";

    format_number(buffer, buffsize, value, 16, digits);
}


/* Perform formatted output to an output target 'o' */
static void
out_vformat(Out *o, const char *format, va_list args)
{
    int nn = 0, mm;
    int padZero = 0;
    int padLeft = 0;
    char sign = '\0';
    int width = -1;
    int prec  = -1;
    size_t bytelen = sizeof(int);
    const char*  str;
    int slen;
    char buffer[32];  /* temporary buffer used to format numbers */

    for (;;) {
        char  c;

        /* first, find all characters that are not 0 or '%' */
        /* then send them to the output directly */
        mm = nn;
        do {
            c = format[mm];
            if (c == '\0' || c == '%')
                break;
            mm++;
        } while (1);

        if (mm > nn) {
            out_send(o, format+nn, mm-nn);
            nn = mm;
        }

        /* is this it ? then exit */
        if (c == '\0')
            break;

        /* nope, we are at a '%' modifier */
        nn++;  // skip it

        /* parse flags */
        for (;;) {
            c = format[nn++];
            if (c == '\0') {  /* single trailing '%' ? */
                c = '%';
                out_send(o, &c, 1);
                return;
            }
            else if (c == '0') {
                padZero = 1;
                continue;
            }
            else if (c == '-') {
                padLeft = 1;
                continue;
            }
            else if (c == ' ' || c == '+') {
                sign = c;
                continue;
            }
            break;
        }

        /* parse field width */
        if ((c >= '0' && c <= '9')) {
            nn --;
            width = (int)parse_decimal(format, &nn);
            c = format[nn++];
        }

        /* parse precision */
        if (c == '.') {
            prec = (int)parse_decimal(format, &nn);
            c = format[nn++];
        }

        /* length modifier */
        switch (c) {
        case 'h':
            bytelen = sizeof(short);
            if (format[nn] == 'h') {
                bytelen = sizeof(char);
                nn += 1;
            }
            c = format[nn++];
            break;
        case 'l':
            bytelen = sizeof(long);
            if (format[nn] == 'l') {
                bytelen = sizeof(long long);
                nn += 1;
            }
            c = format[nn++];
            break;
        case 'z':
            bytelen = sizeof(size_t);
            c = format[nn++];
            break;
        case 't':
            bytelen = sizeof(ptrdiff_t);
            c = format[nn++];
            break;
        case 'p':
            bytelen = sizeof(void*);
            c = format[nn++];
        default:
            ;
        }

        /* conversion specifier */
        if (c == 's') {
            /* string */
            str = va_arg(args, const char*);
        } else if (c == 'c') {
            /* character */
            /* NOTE: char is promoted to int when passed through the stack */
            buffer[0] = (char) va_arg(args, int);
            buffer[1] = '\0';
            str = buffer;
        } else if (c == 'p') {
            uint64_t  value = (uint64_t)(ptrdiff_t) va_arg(args, void*);
            buffer[0] = '0';
            buffer[1] = 'x';
            format_hex(buffer + 2, sizeof buffer-2, value, 0);
            str = buffer;
        } else {
            /* integers - first read value from stack */
            uint64_t value;
            int isSigned = (c == 'd' || c == 'i' || c == 'o');

            /* NOTE: int8_t and int16_t are promoted to int when passed
             *       through the stack
             */
            switch (bytelen) {
            case 1: value = (uint8_t)  va_arg(args, int); break;
            case 2: value = (uint16_t) va_arg(args, int); break;
            case 4: value = va_arg(args, uint32_t); break;
            case 8: value = va_arg(args, uint64_t); break;
            default: return;  /* should not happen */
            }

            /* sign extension, if needed */
            if (isSigned) {
                int shift = 64 - 8*bytelen;
                value = (uint64_t)(((int64_t)(value << shift)) >> shift);
            }

            /* format the number properly into our buffer */
            switch (c) {
            case 'i': case 'd':
                format_integer(buffer, sizeof buffer, value, 10, isSigned);
                break;
            case 'o':
                format_integer(buffer, sizeof buffer, value, 8, isSigned);
                break;
            case 'x': case 'X':
                format_hex(buffer, sizeof buffer, value, (c == 'X'));
                break;
            default:
                buffer[0] = '\0';
            }
            /* then point to it */
            str = buffer;
        }

        /* if we are here, 'str' points to the content that must be
         * outputted. handle padding and alignment now */

        slen = strlen(str);

        if (slen < width && !padLeft) {
            char padChar = padZero ? '0' : ' ';
            out_send_repeat(o, padChar, width - slen);
        }

        out_send(o, str, slen);

        if (slen < width && padLeft) {
            char padChar = padZero ? '0' : ' ';
            out_send_repeat(o, padChar, width - slen);
        }
    }
}


#ifdef UNIT_TESTS

#include <stdio.h>

static int   gFails = 0;

#define  MARGIN  40

#define  UTEST_CHECK(condition,message) \
    printf("Checking %-*s: ", MARGIN, message); fflush(stdout); \
    if (!(condition)) { \
        printf("KO\n"); \
        gFails += 1; \
    } else { \
        printf("ok\n"); \
    }

static void
utest_BufOut(void)
{
    char buffer[16];
    BufOut bo[1];
    Out* out;
    int ret;

    buffer[0] = '1';
    out = buf_out_init(bo, buffer, sizeof buffer);
    UTEST_CHECK(buffer[0] == '\0', "buf_out_init clears initial byte");
    out_send(out, "abc", 3);
    UTEST_CHECK(!memcmp(buffer, "abc", 4), "out_send() works with BufOut");
    out_send_repeat(out, 'X', 4);
    UTEST_CHECK(!memcmp(buffer, "abcXXXX", 8), "out_send_repeat() works with BufOut");
    buffer[sizeof buffer-1] = 'x';
    out_send_repeat(out, 'Y', 2*sizeof(buffer));
    UTEST_CHECK(buffer[sizeof buffer-1] == '\0', "overflows always zero-terminates");

    out = buf_out_init(bo, buffer, sizeof buffer);
    out_send_repeat(out, 'X', 2*sizeof(buffer));
    ret = buf_out_length(bo);
    UTEST_CHECK(ret == 2*sizeof(buffer), "correct size returned on overflow");
}

static void
utest_expect(const char*  result, const char*  format, ...)
{
    va_list args;
    BufOut bo[1];
    char buffer[256];
    Out* out = buf_out_init(bo, buffer, sizeof buffer);

    printf("Checking %-*s: ", MARGIN, format); fflush(stdout);
    va_start(args, format);
    out_vformat(out, format, args);
    va_end(args);

    if (strcmp(result, buffer)) {
        printf("KO. got '%s' expecting '%s'\n", buffer, result);
        gFails += 1;
    } else {
        printf("ok. got '%s'\n", result);
    }
}

int  main(void)
{
    utest_BufOut();
    utest_expect("", "");
    utest_expect("a", "a");
    utest_expect("01234", "01234", "");
    utest_expect("01234", "%s", "01234");
    utest_expect("aabbcc", "aa%scc", "bb");
    utest_expect("a", "%c", 'a');
    utest_expect("1234", "%d", 1234);
    utest_expect("-8123", "%d", -8123);
    utest_expect("16", "%hd", 0x7fff0010);
    utest_expect("16", "%hhd", 0x7fffff10);
    utest_expect("68719476736", "%lld", 0x1000000000);
    utest_expect("70000", "%ld", 70000);
    utest_expect("0xb0001234", "%p", (void*)0xb0001234);
    utest_expect("12ab", "%x", 0x12ab);
    utest_expect("12AB", "%X", 0x12ab);
    utest_expect("00123456", "%08x", 0x123456);
    utest_expect("01234", "0%d", 1234);
    utest_expect(" 1234", "%5d", 1234);
    utest_expect("01234", "%05d", 1234);
    utest_expect("    1234", "%8d", 1234);
    utest_expect("1234    ", "%-8d", 1234);
    utest_expect("abcdef     ", "%-11s", "abcdef");
    utest_expect("something:1234", "%s:%d", "something", 1234);
    return gFails != 0;
}

#endif /* UNIT_TESTS */
