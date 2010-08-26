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
#include <string.h>
#include <stdio.h>
#include <utmp.h>


void pututline(struct utmp* utmp)
{
    FILE* f;
    struct utmp u;
    long i;

    if (!(f = fopen(_PATH_UTMP, "w+")))
        return;

    while (fread(&u, sizeof(struct utmp), 1, f) == 1)
    {
        if (!strncmp(utmp->ut_line, u.ut_line, sizeof(u.ut_line) -1))
        {
            if ((i = ftell(f)) < 0)
                goto ret;
            if (fseek(f, i - sizeof(struct utmp), SEEK_SET) < 0)
                goto ret;
            fwrite(utmp, sizeof(struct utmp), 1, f);
            goto ret;
        }
    }


    fclose(f);

    if (!(f = fopen(_PATH_UTMP, "w+")))
        return;
    fwrite(utmp, sizeof(struct utmp), 1, f);

ret:
    fclose(f);
}
