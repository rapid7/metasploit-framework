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
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
//#include <sys/types.h>

int cpuacct_add(uid_t uid)
{
    int count;
    FILE *fp;
    char buf[80];

    count = snprintf(buf, sizeof(buf), "/acct/uid/%d/tasks", uid);
    fp = fopen(buf, "w+");
    if (!fp) {
        /* Note: sizeof("tasks") returns 6, which includes the NULL char */
        buf[count - sizeof("tasks")] = 0;
        if (mkdir(buf, 0775) < 0)
            return -errno;

        /* Note: sizeof("tasks") returns 6, which includes the NULL char */
        buf[count - sizeof("tasks")] = '/';
        fp = fopen(buf, "w+");
    }
    if (!fp)
        return -errno;

    fprintf(fp, "0");
    if (fclose(fp))
        return -errno;

    return 0;
}
