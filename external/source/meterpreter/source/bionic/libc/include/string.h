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

#ifndef _STRING_H_
#define _STRING_H_

#include <sys/cdefs.h>
#include <stddef.h>
#include <malloc.h>

__BEGIN_DECLS

extern void*  memccpy(void *, const void *, int, size_t);
extern void*  memchr(const void *, int, size_t);
extern void*  memrchr(const void *, int, size_t);
extern int    memcmp(const void *, const void *, size_t);
extern void*  memcpy(void *, const void *, size_t);
extern void*  memmove(void *, const void *, size_t);
extern void*  memset(void *, int, size_t);
extern void*  memmem(const void *, size_t, const void *, size_t);
extern void   memswap(void *, void *, size_t);

extern char*  index(const char *, int);
extern char*  rindex(const char *, int);
extern char*  strchr(const char *, int);
extern char*  strrchr(const char *, int);

extern size_t strlen(const char *);
extern int    strcmp(const char *, const char *);
extern char*  strcpy(char *, const char *);
extern char*  strcat(char *, const char *);

extern int    strcasecmp(const char *, const char *);
extern int    strncasecmp(const char *, const char *, size_t);
extern char*  strdup(const char *);

extern char*  strstr(const char *, const char *);
extern char*  strcasestr(const char *haystack, const char *needle);
extern char*  strtok(char *, const char *);
extern char*  strtok_r(char *, const char *, char**);

extern char*  strerror(int);
extern int    strerror_r(int errnum, char *buf, size_t n);

extern size_t strnlen(const char *, size_t);
extern char*  strncat(char *, const char *, size_t);
extern char*  strndup(const char *, size_t);
extern int    strncmp(const char *, const char *, size_t);
extern char*  strncpy(char *, const char *, size_t);

extern size_t strlcat(char *, const char *, size_t);
extern size_t strlcpy(char *, const char *, size_t);

extern size_t strcspn(const char *, const char *);
extern char*  strpbrk(const char *, const char *);
extern char*  strsep(char **, const char *);
extern size_t strspn(const char *, const char *);

extern char*  strsignal(int  sig);

extern int    strcoll(const char *, const char *);
extern size_t strxfrm(char *, const char *, size_t);

__END_DECLS

#endif /* _STRING_H_ */
