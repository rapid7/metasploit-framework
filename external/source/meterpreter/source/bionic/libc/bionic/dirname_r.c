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
#include <libgen.h>
#include <errno.h>
#include <string.h>
#include <sys/param.h>

int
dirname_r(const char*  path, char*  buffer, size_t  bufflen)
{
    const char *endp;
    int         result, len;

    /* Empty or NULL string gets treated as "." */
    if (path == NULL || *path == '\0') {
        path = ".";
        len  = 1;
        goto Exit;
    }

    /* Strip trailing slashes */
    endp = path + strlen(path) - 1;
    while (endp > path && *endp == '/')
        endp--;

    /* Find the start of the dir */
    while (endp > path && *endp != '/')
        endp--;

    /* Either the dir is "/" or there are no slashes */
    if (endp == path) {
        path = (*endp == '/') ? "/" : ".";
        len  = 1;
        goto Exit;
    }

    do {
        endp--;
    } while (endp > path && *endp == '/');

    len = endp - path +1;

Exit:
    result = len;
    if (len+1 > MAXPATHLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (buffer == NULL)
        return result;

    if (len > (int)bufflen-1) {
        len    = (int)bufflen-1;
        result = -1;
        errno  = ERANGE;
    }

    if (len >= 0) {
        memcpy( buffer, path, len );
        buffer[len] = 0;
    }
    return result;
}
